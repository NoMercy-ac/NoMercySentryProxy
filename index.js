const fs = require('fs');
const util = require('util');
const zlib = require('zlib');
const express = require('express');
const https = require('https');
const http = require('http');
const morgan = require("morgan");
const axios = require("axios");
const request = require('request');
const getRawBody = require('raw-body');
const multipart = require('parse-multipart-data');
const FormData = require('form-data');
const childProc = require('child_process');
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const PORT = 443;
const HOST = "localhost";
// const API_SERVICE_URL = "https://1e47ae045c9a481da525ee51a8460465@o920931.ingest.sentry.io/4505964430229504";
const API_SERVER = "https://api-beta.nomercy.ac";
const SENTRY_PROTOCOL = "https";
const SENTRY_BASE_URL = "o920931.ingest.sentry.io";
const SENTRY_PROJECTS = [
	{
		"name": "client",
		"id": "4505895396179968",
		"key": "2791fac55c7d0024bbf0b31ecb033eeb"
	}
]

const SERVER_OPTIONS = {
	key: fs.readFileSync('./fixtures/key.pem'),
	cert: fs.readFileSync('./fixtures/cert.pem'),
//	ca: fs.readFileSync('./fixtures/ca.pem')
};

const _isNumeric = (value) => {
    return /^-?\d+$/.test(value);
}
const _dumpObject = (obj) => {
	return util.inspect(obj, { showHidden: false, depth: null });
}
const _sendStatus = (res, status) => {
	res.status(status);
	res.end();
}
const _getReleaseValueFromSentryBuffer = (buffer) => {
	const event = buffer.filter(obj => obj.filename == "__sentry-event");
	if (event === undefined || event.length == 0) {
		console.log("No __sentry-event found");
		return undefined;
	}

	const eventData = event[0].data;
	if (eventData === undefined) {
		console.log("No event data found");
		return undefined;
	}

	const eventStr = eventData.toString().replace(/[^\x00-\x7F]/g, "");
	if (eventStr === undefined) {
		console.log("Event data could not be converted to string");
		return undefined;
	}
	if (!eventStr.includes("release")) {
		console.log("Event data does not contain release value");
		return undefined;
	}
	else if (!eventStr.includes("level")) {
		console.log("Event data does not contain level");
		return undefined;
	}

	const releaseID = eventStr.split("release")[1].split("level")[0];
	if (releaseID === undefined) {
		console.log("No release found");
		return undefined;
	}

	return releaseID;
}

const app = express();
app.use(morgan('dev')); // Get traffic logs

app.use((req, res, next) => {
    if (!req.secure) {
		console.log("Redirecting to https...");
		return res.redirect(['https://', req.get('Host'), req.url].join(''));
        // res.redirect(301, `https://${req.hostname}:${PORT}${req.originalUrl}`);
    }
    next();
});

// Do not allow GET requests
app.get('*', (req, res) => {
	console.log(`GET request received to: ${req.url}`);
	res.status(405);
	res.end();
});

app.post('*', async (req, res) => {
	// Log request
	console.log(`POST request received to: ${req.url}`);
	
	console.log("path: " + _dumpObject(req.path));
	console.log("query: " + _dumpObject(req.query));
	console.log("params: " + _dumpObject(req.params));
	console.log("headers: " + _dumpObject(req.headers));
	console.log("files: " + _dumpObject(req.files));

	// Sanity check for user-agent
	const userAgent = req.headers['user-agent'];
	console.log("User-Agent: " + userAgent);

	if (!userAgent) {
		console.log("No user-agent found");
		return _sendStatus(res, 400);
	}

	if (userAgent.indexOf('sentry.native') <= -1 && userAgent.indexOf('Crashpad') <= -1 && userAgent.indexOf('curl/7.78.0-DEV') <= -1) {
		console.log("User-Agent does not contain sentry.native or Crashpad, blocked!");
		return _sendStatus(res, 403);
	}

	// Extract original body from the request
	console.log(`Content-type: ${req.headers['content-type']}`);
	console.log(`Content-length: ${req.headers['content-length']}`);
	console.log(`Content-encoding: ${req.headers['content-encoding']}`);
		console.log("Request is a multipart form, extracting original body from the request");

		try {
			const result = await getRawBody(req, { length: req.headers['content-length'], encoding: req.charset });
			console.log(`Extracted body size: ${result.length}`);

			req.body = result;
		} catch (err) {
			console.log(`getRawBody error: ${err}`);
			return _sendStatus(res, 500);
		}

		// Decompress gzip body if it is gzip encoded
		if (req.headers['content-encoding'] === 'gzip') {
			try {
				const result = await zlib.gunzipSync(req.body);
				console.log(`Decompressed body size: ${result.length}`);

				// fs.writeFileSync(`./temp/original_body.bin`, result);
				req.body = result;
			} catch (err) {
				console.log(`gunzip error: ${err}`);
				return _sendStatus(res, 500);
			}
		}
	// If the request is a multipart form, extract the original body from the request
	if (req.headers['content-type'].indexOf('multipart/form-data') > -1) {


		// Parse multipart form data from the request body and craft new one with processed data
		try {
			let header = req.headers['content-type'];
			console.log(`header: ${header}`);
			let boundary  = header.split(" ")[1];
			boundary = header.split("=")[1];
			console.log("Boundary - "+ boundary);
	
			if (boundary === undefined) {
				console.log("No boundary found");
				return _sendStatus(res, 500);
			}
	
			var form = new FormData();
			form.setBoundary(boundary);

			console.log("Parsing multipart form data from the request body");
	
			let body = req.body;
			let parts = multipart.parse(body, boundary);
			console.log("Parts - " + parts.length);
			for (var i = 0; i < parts.length; i++) {
				var part = parts[i];
				console.log(`#${i} - ${_dumpObject(part)}`);
	
				if (part.filename !== undefined) {
					if (part.filename.endsWith(".dmp")) {
						// Check minidump fixer is exist
						if (!fs.existsSync(path.join(__dirname, "bin", "MiniDumpFixer"))) {
							console.log("Minidump fixer is not found");
						} else {
							const releaseID = _getReleaseValueFromSentryBuffer(parts);
							if (!releaseID) {
								console.log("No release found");
							} else {
								console.log(`Release: '${releaseID}'`);
	
								// Create temp file to store the original file
								const tempPath = path.join(__dirname, "temp");
								if (!fs.existsSync(tempPath)) {
									fs.mkdirSync(tempPath);
								}
	
								// Save minidump to a temporary file
								const tempMinidumpFile = path.join(tempPath, `nm_minidump_file${uuidv4()}`);
								fs.writeFileSync(tempMinidumpFile, part.data);
	
								// Get the original file URL from the API server
								const original_file = "NoMercy_Module_x86_non_rtti.dll.bak"; // TODO: Find better way to get the original file name
								const url = `${API_SERVER}/download_client_file?file_name=${original_file}&file_version=${releaseID}&file_branch=release&file_container=ac_files`;
	
								console.log(`Original file URL: ${url}`);
	
								// Make a axios GET request to the API server to get the original file
								let response = undefined;
								try {
									response = await axios.get(url, { 
										responseType: 'arraybuffer' 
									});
								} catch (err) {
									console.log(`axios error: ${err}`);
									fs.unlinkSync(tempMinidumpFile);
									return _sendStatus(res, 500);
								}
								
								if (response.status !== 200) {
									console.log(`Could not get original file! response: ${_dumpObject(response)}`);
								} else {
									console.log("Original file handled! From: " + response.request.res.responseUrl + " Size: " + response.data.length);
									let fileContent = Buffer.from(response.data, 'binary');
									console.log(`Original file size: ${fileContent.length}`);
	
									// Save the original file to a temporary file
									const tempOrigFile = path.join(tempPath, `nm_client_file_${uuidv4()}`);
									fs.writeFileSync(tempOrigFile, fileContent);
	
									console.log(`Saved original file to ${tempOrigFile}`);
	
									// Run minidump fixer on the temporary file
									const fixer_command = `./bin/MiniDumpFixer ${tempMinidumpFile} ${tempOrigFile}`;
									console.log(`Running minidump fixer: ${fixer_command}`);
	
									let fixer_output = "";
									try {
										fixer_output = childProc.execSync(fixer_command).toString();
									} catch (error) {
										console.log(`Status Code: ${error.status} with '${error.message}'`);
										console.log(`stderr: ${error.stderr.toString()}`);
										console.log(`stdout: ${error.stdout.toString()}`);
									}
									console.log(`Minidump fixer output: ${fixer_output}`);
	
									// Check if the minidump fixer succeeded
									if (!fixer_output.includes("successfully been patched")) {
										console.log("Minidump fixer failed!");
	
										form.append("upload_file_minidump", part.data, {filename: part.filename, contentType: 'application/octet-stream', knownLength: part.data.length});
									} else {
										console.log("Minidump fixer succeeded!");
	
										// Read the processed minidump file
										const fixedMinidumpFile = fs.readFileSync(tempMinidumpFile, 'binary');
	
										// Get minidump processed file hash
										const dumpProcessedHash = crypto.createHash('sha256').update(fixedMinidumpFile).digest('hex').toString();
	
										console.log(`Processed Minidump file: '${tempMinidumpFile} Size: ${fixedMinidumpFile.length} Hash: ${dumpProcessedHash}'`);
	
										const fixedMinidumpBuffer = Buffer.from(fixedMinidumpFile, 'binary');
	
										form.append("upload_file_minidump", fixedMinidumpBuffer, {filename: part.filename, contentType: 'application/octet-stream', knownLength: fixedMinidumpBuffer.length});
									}
	
									// Delete temporary file
									fs.unlinkSync(tempOrigFile);
								}
	
								// Delete the temporary files
								fs.unlinkSync(tempMinidumpFile);
							}
						}
					} else if (part.filename.endsWith(".log")) {
						// TODO: Decrypt log files
	
						form.append(part.filename, part.data, {filename: part.filename, contentType: 'application/octet-stream', knownLength: part.data.length});
					} else {
						form.append(part.filename, part.data, {filename: part.filename, contentType: 'application/octet-stream', knownLength: part.data.length});
					}
				} else {
					form.append(part.name, part.data, {contentType: ''});
				}
			}
	
			// Overwrite headers
			const headers = req.headers;
			// console.log("Original Headers - " + _dumpObject(req.headers));
			req.headers = form.getHeaders();
			// console.log("Created Headers - " + _dumpObject(req.headers));
	
			// Fix some headers
			req.headers['content-type'] = req.headers['content-type'].replaceAll(`"`, "");
			req.headers['content-encoding'] = 'gzip';
			req.headers['user-agent'] = headers['user-agent'];

			// Content must be chunked, so remove content-length
			// req.headers['transfer-encoding'] = 'chunked';

			// Keep content length
			// delete req.headers['content-length'];

			console.log("Final Headers - " + _dumpObject(req.headers));
	
			// Overwrite body
			req.body = form.getBuffer();
			console.log(`Created body size: ${req.body.length}`);
		}
		catch (err) {
			console.log(`multipart create error: ${err}`);
			return _sendStatus(res, 500);
		}

	}

		// Encode again with gzip
		if (req.headers['content-encoding'] === 'gzip') {
			try {
				const result = zlib.gzipSync(req.body);

				console.log("gzip enc result: " + result.length);
				req.body = result;
			} catch (error) {
				console.log(`gzip error: ${err}`);
				return _sendStatus(res, 500);
			}
		}
	console.log("----------------------------------------------------");

	let targeturl = undefined;
	if (req.path.length === 2 || req.path.length === 3) {
		const projectId = req.path.substring(1);
		console.log(`projectId: ${projectId}`);
		if (!_isNumeric(projectId)) {
			console.log("Invalid projectId");
			return _sendStatus(res, 400);
		}

		const project = SENTRY_PROJECTS.find(p => p.id == projectId);
		console.log(`project: ${_dumpObject(project)}`);
		if (!project) {
			console.log("Invalid projectId");
			return _sendStatus(res, 400);
		}

		targeturl = `${SENTRY_PROTOCOL}://${project.key}@${SENTRY_BASE_URL}${req.path}`;
	} else if (req.path.startsWith("/api/")) {
		const projectId = req.path.substring(5).split("/")[0];
		console.log(`projectId: ${projectId}`);
		if (!_isNumeric(projectId)) {
			console.log("Invalid projectId");
			return _sendStatus(res, 400);
		}

		const project = SENTRY_PROJECTS.find(p => p.id == projectId);
		console.log(`project: ${_dumpObject(project)}`);
		if (!project) {
			console.log("Invalid projectId");
			return _sendStatus(res, 400);
		}

		// Check x-sentry-auth header is exist and contains the correct project key
		if (!req.headers['x-sentry-auth'] || req.headers['x-sentry-auth'].indexOf(project.key) === -1) {
			targeturl = `${SENTRY_PROTOCOL}://${SENTRY_BASE_URL}${req.path}/?sentry_key=${project.key}`;
		} else {
			targeturl = `${SENTRY_PROTOCOL}://${SENTRY_BASE_URL}${req.path}`;
		}
	} else {
		console.log(`unknown path: ${req.path}`);
		return _sendStatus(res, 400);
	}
	if (!targeturl) {
		console.log(`unknown project: ${req.path}`);
		return _sendStatus(res, 400);
	}
	console.log(`Sending request to: ${targeturl}`);

	const headers = req.headers;
	console.log("sending headers: " + _dumpObject(Object.keys(headers)));

	request.post({
		url: targeturl,
		headers: headers,
		body: req.body,
		// rejectUnauthorized: false
	}, (err, response, body) => {
		if (err) {
			console.log(`request.post error: ${err}`);
			return res.status(403);
		}

		console.log(`Sentry response: ${response.statusCode} body: ${_dumpObject(body)}`);
	})
	.pipe(res);

	console.log("####################################################");

	console.log(`Status ${res.statusCode}`);
	console.log("headers: " + _dumpObject(res.req.headers));

	return res.end();
});

// http.createServer(app).listen(PORT);
https.createServer(SERVER_OPTIONS, app).listen(PORT);
