const generatorForm = document.getElementById("generatorForm");

const fileInput = document.getElementById("requirementsFile");
const uploadArea = document.getElementById("uploadArea");

const selectedFileBox = document.getElementById("selectedFile");
const fileName = document.getElementById("fileName");
const fileSize = document.getElementById("fileSize");
const removeFileButton = document.getElementById("removeFile");

const scenarioCount = document.getElementById("scenarioCount");

const generateButton = document.getElementById("generateButton");
const buttonText = document.getElementById("buttonText");
const loadingSpinner = document.getElementById("loadingSpinner");

const statusMessage = document.getElementById("statusMessage");

const resultSection = document.getElementById("resultSection");
const viewReport = document.getElementById("viewReport");
const downloadReport = document.getElementById("downloadReport");


/* =========================================================
   STATE
========================================================= */

let selectedFile = null;


/* =========================================================
   INITIAL STATE
========================================================= */

if (selectedFileBox) {
  selectedFileBox.hidden = true;
}

if (resultSection) {
  resultSection.hidden = true;
}

if (statusMessage) {
  statusMessage.hidden = true;
}

if (loadingSpinner) {
  loadingSpinner.hidden = true;
}


/* =========================================================
   FILE SIZE
========================================================= */

function formatFileSize(bytes) {

  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}


/* =========================================================
   STATUS
========================================================= */

function showStatus(message, type) {

  if (!statusMessage) {
    return;
  }

  statusMessage.textContent = message;
  statusMessage.hidden = false;

  statusMessage.className =
    `status-message ${type || ""}`;
}


function hideStatus() {

  if (!statusMessage) {
    return;
  }

  statusMessage.textContent = "";
  statusMessage.hidden = true;
  statusMessage.className =
    "status-message";
}


/* =========================================================
   RESET REPORT
========================================================= */

function resetReport() {

  if (resultSection) {
    resultSection.hidden = true;
  }

  if (viewReport) {
    viewReport.removeAttribute("href");
  }

  if (downloadReport) {
    downloadReport.removeAttribute("href");
  }
}


/* =========================================================
   RESET FILE
========================================================= */

function resetFile() {

  selectedFile = null;


  if (fileInput) {
    fileInput.value = "";
  }


  if (selectedFileBox) {
    selectedFileBox.hidden = true;
  }


  if (fileName) {
    fileName.textContent = "";
  }


  if (fileSize) {
    fileSize.textContent = "";
  }


  resetReport();
  hideStatus();


  if (generateButton) {
    generateButton.disabled = false;
  }


  if (buttonText) {
    buttonText.textContent =
      "Generate Security Report";
  }


  if (loadingSpinner) {
    loadingSpinner.hidden = true;
  }
}


/* =========================================================
   DISPLAY FILE
========================================================= */

function displayFile(file) {

  if (!file) {
    return;
  }


  selectedFile = file;


  /*
    New file = remove previous report.
  */

  resetReport();
  hideStatus();


  if (fileName) {
    fileName.textContent =
      file.name;
  }


  if (fileSize) {
    fileSize.textContent =
      formatFileSize(file.size);
  }


  if (selectedFileBox) {
    selectedFileBox.hidden = false;
  }
}


/* =========================================================
   FILE SELECT
========================================================= */

if (fileInput) {

  fileInput.addEventListener(
    "change",
    function () {

      const file =
        fileInput.files &&
        fileInput.files[0];


      if (!file) {
        return;
      }


      displayFile(file);

    }
  );

}


/* =========================================================
   REMOVE FILE
========================================================= */

if (removeFileButton) {

  removeFileButton.addEventListener(
    "click",
    function (event) {

      event.preventDefault();
      event.stopPropagation();

      resetFile();

    }
  );

}


/* =========================================================
   UPLOAD AREA
========================================================= */

if (uploadArea) {

  uploadArea.addEventListener(
    "dragover",
    function (event) {

      event.preventDefault();

      uploadArea.classList.add(
        "drag-over"
      );

    }
  );


  uploadArea.addEventListener(
    "dragleave",
    function () {

      uploadArea.classList.remove(
        "drag-over"
      );

    }
  );


  uploadArea.addEventListener(
    "drop",
    function (event) {

      event.preventDefault();

      uploadArea.classList.remove(
        "drag-over"
      );


      const files =
        event.dataTransfer.files;


      if (!files || !files.length) {
        return;
      }


      const file = files[0];


      /*
        Put dropped file into the real
        file input.
      */

      try {

        const dataTransfer =
          new DataTransfer();

        dataTransfer.items.add(file);

        fileInput.files =
          dataTransfer.files;

      } catch (error) {

        console.warn(
          "Could not assign dropped file.",
          error
        );

      }


      displayFile(file);

    }
  );

}


/* =========================================================
   GENERATE REPORT
========================================================= */

if (generatorForm) {

  generatorForm.addEventListener(
    "submit",
    async function (event) {

      event.preventDefault();


      /* -----------------------------------------------
         CHECK FILE
      ----------------------------------------------- */

      if (!selectedFile) {

        showStatus(
          "Please upload a requirements file first.",
          "error"
        );

        return;
      }


      /* -----------------------------------------------
         REMOVE OLD RESULT
      ----------------------------------------------- */

      resetReport();
      hideStatus();


      /* -----------------------------------------------
         LOADING
      ----------------------------------------------- */

      generateButton.disabled = true;


      buttonText.textContent =
        "Generating Security Report...";


      loadingSpinner.hidden = false;


      /* -----------------------------------------------
         FORM DATA
      ----------------------------------------------- */

      const formData =
        new FormData();


      formData.append(
        "requirementsFile",
        selectedFile
      );


      formData.append(
        "scenarioCount",
        scenarioCount
          ? scenarioCount.value
          : "5"
      );


      /* -----------------------------------------------
         TIMEOUT
      ----------------------------------------------- */

      const controller =
        new AbortController();


      const timeout =
        setTimeout(
          function () {

            controller.abort();

          },
          120000
        );


      try {

        showStatus(
          "Generating your security scenarios. Please wait...",
          "info"
        );


        console.log(
          "Sending file to server:",
          selectedFile.name
        );


        /* -------------------------------------------
           SEND TO SERVER
        ------------------------------------------- */

        const response =
          await fetch(
            "/api/generate",
            {
              method: "POST",
              body: formData,
              signal: controller.signal
            }
          );


        console.log(
          "Server response:",
          response.status
        );


        /* -------------------------------------------
           READ JSON
        ------------------------------------------- */

        const data =
          await response.json();


        console.log(
          "Server data:",
          data
        );


        if (
          !response.ok ||
          !data.success
        ) {

          throw new Error(
            data.message ||
            "Failed to generate security report."
          );

        }


        /* -------------------------------------------
           SUCCESS
        ------------------------------------------- */

        clearTimeout(timeout);


        showStatus(
          "Security report generated successfully.",
          "success"
        );


        if (resultSection) {
          resultSection.hidden = false;
        }


        /* -------------------------------------------
           HTML REPORT
        ------------------------------------------- */

        if (
          data.report &&
          data.report.html
        ) {

          viewReport.href =
            data.report.html;

          viewReport.target =
            "_blank";

        }


        /* -------------------------------------------
           MARKDOWN REPORT
        ------------------------------------------- */

        if (
          data.report &&
          data.report.markdown
        ) {

          downloadReport.href =
            data.report.markdown;

          downloadReport.setAttribute(
            "download",
            ""
          );

        }


      } catch (error) {

        clearTimeout(timeout);


        console.error(
          "Generation error:",
          error
        );


        if (
          error.name ===
          "AbortError"
        ) {

          showStatus(
            "Report generation timed out. Check the VS Code terminal.",
            "error"
          );

        } else {

          showStatus(
            error.message ||
            "Something went wrong while generating the report.",
            "error"
          );

        }


        resetReport();

      } finally {

        clearTimeout(timeout);


        generateButton.disabled =
          false;


        buttonText.textContent =
          "Generate Security Report";


        loadingSpinner.hidden =
          true;

      }

    }
  );

}


/* =========================================================
   DEBUG MESSAGE
========================================================= */

console.log(
  "Security Scenario Generator frontend loaded successfully."
);

console.log(
  "File input:",
  fileInput
);

console.log(
  "Remove button:",
  removeFileButton
);

console.log(
  "Generate button:",
  generateButton
);

console.log(
  "Generator form:",
  generatorForm
);