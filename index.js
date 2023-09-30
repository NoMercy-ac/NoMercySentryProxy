const fs = require('fs');
const util = require('util');
const zlib = require('zlib');
const express = require('express');
const https = require('https');
const http = require('http');
const morgan = require("morgan");
const axios = require("axios");
const requests = require('request');
const getRawBody = require('raw-body');
const multipart = require('parse-multipart-data');
const FormData = require('form-data');
const childProc = require('child_process');
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const Sentry = require('@sentry/node');

const PORT = 443;
const HOST = "localhost";
// const API_SERVICE_URL = "https://2791fac55c7d0024bbf0b31ecb033eeb@o920931.ingest.sentry.io/4505895396179968";
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
	cert: fs.readFileSync('./fixtures/cert.pem')
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

	let releaseID = eventStr.split("release")[1].split("level")[0];
	if (releaseID === undefined) {
		console.log("No release found");
		return undefined;
	}
	console.log("Release: " + releaseID);

	const cleanedStr = releaseID.replace(/[^0-9.]/g, '');
	if (cleanedStr === undefined) {
		throw new Error("Release could not be cleaned");
	} else {
		releaseID = cleanedStr;
	}
	console.log("Cleaned release: " + releaseID);

	return releaseID;
}

const app = express();
app.use(morgan('dev')); // Get traffic logs

Sentry.init({
	dsn: "https://4d1f41a1bb21666f16d485330c21c11a@o920931.ingest.sentry.io/4505965966327808",
	
	integrations: [
	  // enable HTTP calls tracing
	  new Sentry.Integrations.Http({ tracing: true }),
	  // enable Express.js middleware tracing
	  new Sentry.Integrations.Express({ app }),
	],
  
	// Set tracesSampleRate to 1.0 to capture 100%
	// of transactions for performance monitoring.
	// We recommend adjusting this value in production
	tracesSampleRate: 1.0,
  });
  
  /*
// RequestHandler creates a separate execution context using domains, so that every
// transaction/span/breadcrumb is attached to its own Hub instance
app.use(Sentry.Handlers.requestHandler());
// TracingHandler creates a trace for every incoming request
app.use(Sentry.Handlers.tracingHandler());	
*/
// The error handler must be before any other error middleware and after all controllers
app.use(Sentry.Handlers.errorHandler());

app.get('/operational', (req, res) => {
	res.writeHead(200);
	res.end();
});

app.use((req, res, next) => {
//	/*
    if (!req.secure) {
		console.log("*** Redirecting to https...");
		return res.redirect(['https://', req.get('Host'), req.url].join(''));
	}
//	*/
    next();
});

// Do not allow GET requests
app.get('*', (req, res) => {
//	/*
	console.log(`GET request received to: ${req.url}`);
	res.status(405);
	res.end();
//	*/
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

	if (userAgent.indexOf('sentry.native') <= -1 && userAgent.indexOf('Crashpad') <= -1 &&
		userAgent.indexOf('curl/7.78.0-DEV') <= -1 && userAgent.indexOf('curl/7.80.0') <= -1) {
		console.log("User-Agent does not contain sentry.native or Crashpad, blocked!");
//		if (userAgent.indexOf('insomnia/2023.4.0') <= -1) {
			return _sendStatus(res, 402);
//		}
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
			throw new Error(`getRawBody error: ${err}`);
			// return _sendStatus(res, 500);
		}

		// Decompress gzip body if it is gzip encoded
		if (req.headers['content-encoding'] === 'gzip') {
			try {
				const result = await zlib.gunzipSync(req.body);
				console.log(`Decompressed body size: ${result.length}`);

				// fs.writeFileSync(`./temp/original_body.bin`, result);
				req.body = result;
			} catch (err) {
				throw new Error(`gunzip error: ${err}`);
				// return _sendStatus(res, 500);
			}
		}
	// If the request is a multipart form, extract the original body from the request
	const contentType = req.headers['content-type'];
	if (!contentType) {
		throw new Error("No content-type found");
		//return _sendStatus(res, 400);
	}

	if (contentType.indexOf('multipart/form-data') > -1) {


		// Parse multipart form data from the request body and craft new one with processed data
		try {
			let header = req.headers['content-type'];
			console.log(`header: ${header}`);
			let boundary  = header.split(" ")[1];
			boundary = header.split("=")[1];
			console.log("Boundary - "+ boundary);
	
			if (boundary === undefined) {
				throw new Error("No boundary found");
				//return _sendStatus(res, 500);
			}
	
			var form = new FormData();
			form.setBoundary(boundary);

			console.log(`Parsing multipart form data from the request body with size: ${req.body.length}`);
	
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
	
								// TODO: Make a new api endpoint for getting required PE values from pre-registired list, don't get whole file and analyze again and again
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
									fs.unlinkSync(tempMinidumpFile);
									throw new Error(`axios error: ${err}`);
									// return _sendStatus(res, 500);
								}
								
								if (response.status !== 200) {
									throw new Error(`Could not get original file! response: ${_dumpObject(response)}`);
								} else {
									console.log("Original file handled! From: " + response.request.res.responseUrl + " Size: " + response.data.length);
									let fileContent = Buffer.from(response.data, 'binary');
									console.log(`Original file size: ${fileContent.length}`);
	
									// Save the original file to a temporary file
									const tempOrigFile = path.join(tempPath, `nm_client_file_${uuidv4()}`);
									fs.writeFileSync(tempOrigFile, fileContent);
	
									console.log(`Saved original file to ${tempOrigFile}`);
	
									// Run minidump fixer on the temporary file
									let fixer_command = `./bin/MiniDumpFixer ${tempMinidumpFile} ${tempOrigFile}`;
									console.log(`Running minidump fixer: ${fixer_command}`);
	
									let fixer_output = "";
									try {
										fixer_output = childProc.execSync(fixer_command).toString();
									} catch (error) {
										console.log(`Status Code: ${error.status} with '${error.message}'`);
										console.log(`stderr: ${error.stderr.toString()}`);
										console.log(`stdout: ${error.stdout.toString()}`);
										throw new Error(`Minidump fixer error: ${error.message}`);
									}
									console.log(`Minidump fixer output: ${fixer_output}`);
/*
									// Run minidump fixer for the client binary
									{
										let fixer_command2 = `./bin/MiniDumpFixer ${tempMinidumpFile} ./bin/smt.exe`;
										console.log(`Running minidump fixer: ${fixer_command2}`);
		
										let fixer_output2 = "";
										try {
											fixer_output2 = childProc.execSync(fixer_command2).toString();
										} catch (error) {
											console.log(`2 Status Code: ${error.status} with '${error.message}'`);
											console.log(`2 stderr: ${error.stderr.toString()}`);
											console.log(`2 stdout: ${error.stdout.toString()}`);
											// throw new Error(`Minidump fixer2 error: ${error.message}`);
										}
										console.log(`Minidump fixer2 output: ${fixer_output2}`);
									}
	*/
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
			throw new Error(`multipart create error: ${err}`);
		//	return _sendStatus(res, 500);
		}

	}

		// Encode again with gzip
		if (req.headers['content-encoding'] === 'gzip') {
			try {
				const result = zlib.gzipSync(req.body);

				console.log("gzip enc result: " + result.length);
				req.body = result;
			} catch (error) {
				throw new Error(`gzip error: ${err}`);
			//	return _sendStatus(res, 500);
			}
		}
	console.log("----------------------------------------------------");

	let targeturl = undefined;
	if (req.path.length === 2 || req.path.length === 3) {
		const projectId = req.path.substring(1);
		console.log(`projectId: ${projectId}`);
		if (!_isNumeric(projectId)) {
			console.log(`Invalid projectId 1: ${projectId}`);
			return _sendStatus(res, 400);
		}

		const project = SENTRY_PROJECTS.find(p => p.id == projectId);
		console.log(`project: ${_dumpObject(project)}`);
		if (!project) {
			throw new Error(`Invalid projectId 2: ${projectId}`);
			//return _sendStatus(res, 400);
		}

		targeturl = `${SENTRY_PROTOCOL}://${project.key}@${SENTRY_BASE_URL}${req.path}`;
	} else if (req.path.startsWith("/api/")) {
		const projectId = req.path.substring(5).split("/")[0];
		console.log(`projectId: ${projectId}`);
		if (!_isNumeric(projectId)) {
			throw new Error(`Invalid projectId 3: ${projectId}`);
			//return _sendStatus(res, 400);
		}

		const project = SENTRY_PROJECTS.find(p => p.id == projectId);
		console.log(`project: ${_dumpObject(project)}`);
		if (!project) {
			throw new Error(`Invalid projectId 4: ${projectId}`);
			// return _sendStatus(res, 400);
		}

		// Check x-sentry-auth header is exist and contains the correct project key
		if (!req.headers['x-sentry-auth'] || req.headers['x-sentry-auth'].indexOf(project.key) === -1) {
			targeturl = `${SENTRY_PROTOCOL}://${SENTRY_BASE_URL}${req.path}/?sentry_key=${project.key}`;
		} else {
			targeturl = `${SENTRY_PROTOCOL}://${SENTRY_BASE_URL}${req.path}`;
		}
	} else {
		throw new Error(`unknown path: ${req.path}`);
		// return _sendStatus(res, 400);
	}
	if (!targeturl) {
		throw new Error(`unknown project: ${req.path}`);
		// return _sendStatus(res, 400);
	}
	console.log(`Sending request to: ${targeturl}`);

	const headers = req.headers;
	console.log("sending headers: " + _dumpObject(Object.keys(headers)));

	// Send request
	requests.post({
		url: targeturl,
		headers: headers,
		body: req.body,
		// rejectUnauthorized: false
	}, (err, response, body) => {
		if (err) {
			throw new Error(`request.post error: ${err}`);
			//return res.status(403);
		}

		console.log(`Sentry response: ${response.statusCode} body: ${_dumpObject(body)}`);
	})
	.pipe(res);

	console.log("####################################################");

	console.log(`Status ${res.statusCode}`);
	console.log("headers: " + _dumpObject(res.req.headers));

	return res.end();
});

//http.createServer(app).listen(80);
https.createServer(SERVER_OPTIONS, app).listen(PORT);
