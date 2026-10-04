const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");

const app = express();

const PORT = 3000;

const ROOT_DIR = __dirname;

const PUBLIC_DIR = path.join(ROOT_DIR, "public");
const UPLOADS_DIR = path.join(ROOT_DIR, "uploads");
const REPORTS_DIR = path.join(ROOT_DIR, "reports");

const GENERATOR = path.join(
  ROOT_DIR,
  "security-scenario-generator-current.js"
);


/* =========================================================
   CREATE REQUIRED DIRECTORIES
========================================================= */

if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

if (!fs.existsSync(REPORTS_DIR)) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
}


/* =========================================================
   MULTER UPLOAD CONFIGURATION
========================================================= */

const storage = multer.diskStorage({

  destination: function (req, file, cb) {
    cb(null, UPLOADS_DIR);
  },

  filename: function (req, file, cb) {

    const extension =
      path.extname(file.originalname);

    const baseName =
      path.basename(
        file.originalname,
        extension
      )
        .replace(/[^a-zA-Z0-9-_]/g, "_");

    const uniqueName =
      `${baseName}-${Date.now()}${extension}`;

    cb(null, uniqueName);
  }

});

const allowedExtensions = [
  ".txt",
  ".md",
  ".markdown",
  ".html",
  ".htm",
  ".docx",
  ".pdf"
];


const upload = multer({

  storage: storage,

  limits: {
    fileSize: 10 * 1024 * 1024
  },

  fileFilter: function (req, file, cb) {

    const extension =
      path.extname(file.originalname).toLowerCase();

    if (!allowedExtensions.includes(extension)) {

      return cb(
        new Error(
          "Unsupported file type. Please upload TXT, MD, HTML, DOCX or PDF."
        )
      );

    }

    cb(null, true);

  }

});


/* =========================================================
   SERVE FRONTEND
========================================================= */

app.use(
  express.static(PUBLIC_DIR)
);


/* =========================================================
   REPORT ROUTES
========================================================= */

/*
   IMPORTANT:

   These routes are BEFORE the frontend fallback.

   This prevents /reports/something.html from accidentally
   returning public/index.html.
*/


app.get("/reports/:filename", function (req, res) {

  const requestedFile = req.params.filename;

  // Prevent path traversal.
  const safeFileName = path.basename(requestedFile);

  const reportPath =
    path.join(REPORTS_DIR, safeFileName);


  if (!fs.existsSync(reportPath)) {

    return res.status(404).send(
      "Report file not found."
    );

  }


  const extension =
    path.extname(safeFileName).toLowerCase();


  if (extension === ".html") {

    res.type("html");

    return res.sendFile(reportPath);

  }


  if (extension === ".md") {

    res.type("text/markdown");

    return res.sendFile(reportPath);

  }


  return res.status(400).send(
    "Invalid report type."
  );

});


/* =========================================================
   MARKDOWN DOWNLOAD ROUTE
========================================================= */

app.get(
  "/reports/:filename/download",
  function (req, res) {

    const requestedFile =
      req.params.filename;

    const safeFileName =
      path.basename(requestedFile);

    const reportPath =
      path.join(REPORTS_DIR, safeFileName);


    if (!fs.existsSync(reportPath)) {

      return res.status(404).send(
        "Markdown report not found."
      );

    }


    return res.download(
      reportPath,
      safeFileName
    );

  }
);


/* =========================================================
   FIND NEWEST REPORT
========================================================= */

function findNewestReport(extension, sourceFileName) {

  const files =
    fs.readdirSync(REPORTS_DIR);


  const sourceBase =
    path.basename(
      sourceFileName,
      path.extname(sourceFileName)
    )
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");


  const matchingFiles = files
    .filter(function (file) {

      return (
        path.extname(file).toLowerCase() === extension &&
        file.toLowerCase().startsWith(sourceBase)
      );

    })
    .map(function (file) {

      const fullPath =
        path.join(REPORTS_DIR, file);

      return {
        file,
        path: fullPath,
        time: fs.statSync(fullPath).mtimeMs
      };

    })
    .sort(function (a, b) {

      return b.time - a.time;

    });


  if (matchingFiles.length === 0) {
    return null;
  }


  return matchingFiles[0].path;

}


/* =========================================================
   RUN SECURITY SCENARIO GENERATOR
========================================================= */

function runGenerator(
  inputFile,
  perCategory
) {

  return new Promise(function (resolve, reject) {

    const args = [
      GENERATOR,
      inputFile
    ];


    /*
      The generator supports:

      --per-category N

      Your dropdown can therefore control
      the actual generator.
    */

    if (perCategory) {

      args.push(
        "--per-category",
        String(perCategory)
      );

    }


    console.log("");
    console.log("==========================================");
    console.log("Starting security scenario generator...");
    console.log("==========================================");
    console.log("Input:", inputFile);
    console.log("Arguments:", args);
    console.log("");


    const child = spawn(
      process.execPath,
      args,
      {
        cwd: ROOT_DIR,

        windowsHide: true,

        stdio: [
          "ignore",
          "pipe",
          "pipe"
        ]
      }
    );


    let stdout = "";
    let stderr = "";


    child.stdout.on(
      "data",
      function (data) {

        const text =
          data.toString();

        stdout += text;

        console.log(
          "[Generator]",
          text.trim()
        );

      }
    );


    child.stderr.on(
      "data",
      function (data) {

        const text =
          data.toString();

        stderr += text;

        console.error(
          "[Generator Error]",
          text.trim()
        );

      }
    );


    child.on(
      "error",
      function (error) {

        reject(error);

      }
    );


    child.on(
      "close",
      function (code) {

        console.log("");
        console.log(
          "Generator exited with code:",
          code
        );


        if (code !== 0) {

          return reject(
            new Error(
              stderr ||
              stdout ||
              `Generator exited with code ${code}`
            )
          );

        }


        resolve({
          stdout,
          stderr
        });

      }
    );


    /*
      Safety timeout.

      If something goes wrong and the generator
      never exits, the website won't stay loading forever.
    */

    const timeout = setTimeout(
      function () {

        try {

          child.kill();

        } catch (error) {

          console.error(error);

        }


        reject(
          new Error(
            "Security scenario generator timed out."
          )
        );

      },
      120000
    );


    child.on(
      "close",
      function () {

        clearTimeout(timeout);

      }
    );

  });

}


/* =========================================================
   GENERATE API
========================================================= */

app.post(
  "/api/generate",
  upload.single("requirementsFile"),

  async function (req, res) {

    let uploadedFile = null;


    try {

      /* ---------------------------------------------
         CHECK FILE
      --------------------------------------------- */

      if (!req.file) {

        return res.status(400).json({

          success: false,

          message:
            "Please upload a requirements file."

        });

      }


      uploadedFile =
        req.file.path;


      console.log("");
      console.log("==========================================");
      console.log("File uploaded");
      console.log("==========================================");
      console.log(
        "Original name:",
        req.file.originalname
      );
      console.log(
        "Saved path:",
        uploadedFile
      );


      /* ---------------------------------------------
         SCENARIO COUNT
      --------------------------------------------- */

      let perCategory =
        parseInt(
          req.body.scenarioCount,
          10
        );


      if (
        !Number.isInteger(perCategory) ||
        perCategory < 1 ||
        perCategory > 6
      ) {

        perCategory = 5;

      }


      console.log(
        "Scenarios per category:",
        perCategory
      );


      /* ---------------------------------------------
         RUN EXISTING GENERATOR
      --------------------------------------------- */

      await runGenerator(
        uploadedFile,
        perCategory
      );


      /* ---------------------------------------------
         FIND REPORTS
      --------------------------------------------- */

      const htmlReport =
        findNewestReport(
          ".html",
          req.file.originalname
        );


      const markdownReport =
        findNewestReport(
          ".md",
          req.file.originalname
        );


      console.log("");
      console.log("==========================================");
      console.log("Reports found");
      console.log("==========================================");

      console.log(
        "HTML:",
        htmlReport
      );

      console.log(
        "Markdown:",
        markdownReport
      );


      if (!htmlReport || !markdownReport) {

        throw new Error(
          "The generator completed, but the generated report files could not be found."
        );

      }


      /* ---------------------------------------------
         CONVERT WINDOWS PATHS TO WEB URLS
      --------------------------------------------- */

      const htmlFileName =
        path.basename(htmlReport);

      const markdownFileName =
        path.basename(markdownReport);


      const htmlUrl =
        `/reports/${encodeURIComponent(htmlFileName)}`;


      const markdownUrl =
        `/reports/${encodeURIComponent(markdownFileName)}/download`;


      /* ---------------------------------------------
         SUCCESS RESPONSE
      --------------------------------------------- */

      return res.json({

        success: true,

        message:
          "Security report generated successfully.",

        fileName:
          req.file.originalname,

        report: {

          html:
            htmlUrl,

          markdown:
            markdownUrl

        }

      });


    } catch (error) {

      console.error("");
      console.error("==========================================");
      console.error("GENERATION ERROR");
      console.error("==========================================");

      console.error(error);


      return res.status(500).json({

        success: false,

        message:
          error.message ||
          "Failed to generate the security report."

      });


    } finally {

      /*
        Delete the temporary uploaded file.

        The generated reports remain in /reports.
      */

      if (
        uploadedFile &&
        fs.existsSync(uploadedFile)
      ) {

        try {

          fs.unlinkSync(
            uploadedFile
          );

        } catch (error) {

          console.error(
            "Could not delete temporary upload:",
            error.message
          );

        }

      }

    }

  }
);


/* =========================================================
   API HEALTH CHECK
========================================================= */

app.get(
  "/api/health",
  function (req, res) {

    res.json({

      success: true,

      message:
        "Security Scenario Generator server is running."

    });

  }
);


/* =========================================================
   FRONTEND FALLBACK
========================================================= */

/*
   Keep this LAST.

   This is important.

   If the browser asks for an unknown frontend URL,
   return index.html.

   Report URLs have already been handled above.
*/

app.use(function (req, res) {
  res.sendFile(
    path.join(
      PUBLIC_DIR,
      "index.html"
    )
  );
});


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  function (error, req, res, next) {

    console.error(
      "Server error:",
      error
    );


    if (res.headersSent) {

      return next(error);

    }


    res.status(500).json({

      success: false,

      message:
        error.message ||
        "Server error."

    });

  }
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  function () {

    console.log("");
    console.log("==========================================");
    console.log("Security Scenario Generator");
    console.log("==========================================");
    console.log(
      `Website: http://localhost:${PORT}`
    );
    console.log(
      `Reports: ${REPORTS_DIR}`
    );
    console.log("==========================================");
    console.log("");

  }
);