import React, {
  useEffect,
  useState
} from "react";


const API =
  "https://vulnscan-backend-production.up.railway.app";


async function api(
  endpoint,
  options = {}
) {
  const response = await fetch(
    API + endpoint,
    {
      credentials: "include",

      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {})
      },

      ...options
    }
  );


  const data =
    await response
      .json()
      .catch(() => ({}));


  if (!response.ok) {
    throw new Error(
      data.error ||
      "Request failed"
    );
  }


  return data;
}


/* =========================
   SCORE GAUGE
========================= */

function Gauge({
  score
}) {
  return (
    <div
      className="gauge"
      style={{
        "--score": score ?? 0
      }}
    >
      <div className="gauge-value">
        {score ?? "--"}
      </div>

      <div className="gauge-label">
        /100
      </div>
    </div>
  );
}


/* =========================
   SECURITY CHECKS
========================= */

function Checks({
  title,
  items = []
}) {
  return (
    <section>

      <h3>
        {title}
      </h3>


      {items.length === 0 ? (

        <p className="muted">
          None
        </p>

      ) : (

        items.map(
          (
            item,
            index
          ) => (

            <article
              key={
                item.id ||
                index
              }

              className={
                item.passed
                  ? "check pass"
                  : "check fail"
              }
            >

              <h4>
                {item.title}
              </h4>


              <p>
                {item.evidence}
              </p>


              {!item.passed && (

                <p>

                  <strong>
                    How to fix:
                  </strong>{" "}

                  {item.remediation}

                </p>

              )}

            </article>

          )
        )

      )}

    </section>
  );
}


/* =========================
   MAIN APP
========================= */

export default function App() {

  const [
    user,
    setUser
  ] = useState(null);


  const [
    email,
    setEmail
  ] = useState(
    "demo@vulnscan.local"
  );


  const [
    password,
    setPassword
  ] = useState(
    "Demo123!"
  );


  const [
    register,
    setRegister
  ] = useState(false);


  const [
    url,
    setUrl
  ] = useState(
    "https://example.com"
  );


  const [
    scan,
    setScan
  ] = useState(null);


  const [
    history,
    setHistory
  ] = useState([]);


  const [
    error,
    setError
  ] = useState("");


  /* =========================
     LOAD SCAN HISTORY
  ========================= */

  async function loadHistory() {

    try {

      const data =
        await api(
          "/api/history"
        );


      setHistory(
        data.scans || []
      );

    } catch {
      // User may not be logged in.
    }
  }


  /* =========================
     LOGIN / REGISTER
  ========================= */

  async function handleLogin() {

    setError("");


    try {

      /* =========================
         CREATE NEW ACCOUNT
      ========================= */

      if (register) {

        /*
          Clear any previous account
          session before registration.
        */

        try {

          await api(
            "/api/auth/logout",
            {
              method: "POST"
            }
          );

        } catch {
          // Continue registration.
        }


        /*
          Clear previous account's
          frontend data.
        */

        setUser(null);
        setScan(null);
        setHistory([]);


        /*
          Create the new account.
        */

        await api(
          "/api/auth/register",
          {
            method: "POST",

            body: JSON.stringify({
              email,
              password
            })
          }
        );


        /*
          Registration does not automatically
          log the new user in.

          Return to login mode.
        */

        setRegister(false);

        setPassword("");

        setError(
          "Account created successfully. Please login with your new account."
        );

        return;
      }


      /* =========================
         NORMAL LOGIN
      ========================= */

      const data =
        await api(
          "/api/auth/login",
          {
            method: "POST",

            body: JSON.stringify({
              email,
              password
            })
          }
        );


      /*
        Set the newly authenticated user.
      */

      setUser(
        data.user
      );


      /*
        Clear any previous frontend
        account data before loading
        the new user's history.
      */

      setScan(null);
      setHistory([]);


      /*
        Load history belonging to
        the newly logged-in user.
      */

      await loadHistory();

    } catch (error) {

      setError(
        error.message
      );
    }
  }


  /* =========================
     LOGOUT
  ========================= */

  async function handleLogout() {

    try {

      await api(
        "/api/auth/logout",
        {
          method: "POST"
        }
      );

    } catch {
      // Continue logout locally.
    }


    /*
      Clear all account-specific
      frontend data.
    */

    setUser(null);
    setScan(null);
    setHistory([]);
    setError("");

    setRegister(false);
  }


  /* =========================
     START SCAN
  ========================= */

  async function startScan() {

    setError("");


    if (!url.trim()) {

      setError(
        "Please enter a website URL."
      );

      return;
    }


    /*
      Immediately show QUEUED
      while waiting for backend.
    */

    setScan({
      status: "QUEUED",
      url: url
    });


    try {

      const data =
        await api(

          "/api/scan",

          {
            method: "POST",

            body: JSON.stringify({
              url
            })
          }
        );


      /*
        Store the actual scan ID
        returned by Railway.
      */

      setScan({

        id:
          data.scan_id,

        task_id:
          data.task_id,

        url:
          url,

        status:
          data.status || "QUEUED"

      });

    } catch (error) {

      setError(
        error.message
      );

      setScan(null);
    }
  }


  /* =========================
     SCAN STATUS POLLING
  ========================= */

  useEffect(() => {

    if (!scan?.id) {
      return;
    }


    let cancelled = false;
    let interval = null;


    /*
      Function that checks the
      current scan status.
    */

    const checkScanStatus =
      async () => {

        try {

          const data =
            await api(
              `/api/scan/${scan.id}/status`
            );


          if (cancelled) {
            return;
          }


          /*
            Update the entire scan
            object with the latest
            backend response.
          */

          setScan(
            data
          );


          /*
            Scan completed.
          */

          if (
            data.status ===
            "COMPLETED"
          ) {

            if (interval) {
              clearInterval(
                interval
              );
            }


            await loadHistory();

            return;
          }


          /*
            Scan failed.
          */

          if (
            data.status ===
            "FAILED"
          ) {

            if (interval) {
              clearInterval(
                interval
              );
            }


            await loadHistory();

            return;
          }


        } catch (error) {

          if (cancelled) {
            return;
          }


          setError(
            error.message
          );


          if (interval) {
            clearInterval(
              interval
            );
          }
        }
      };


    /*
      Check immediately.
    */

    checkScanStatus();


    /*
      Continue checking every
      2 seconds.
    */

    interval =
      setInterval(
        checkScanStatus,
        2000
      );


    /*
      Cleanup when scan changes
      or component unmounts.
    */

    return () => {

      cancelled = true;

      if (interval) {
        clearInterval(
          interval
        );
      }
    };


  }, [scan?.id]);


  /* =========================
     LOGIN PAGE
  ========================= */

  if (!user) {

    return (

      <main className="auth">

        <section className="card auth-card">

          <h1>
            VulnScan-Lite
          </h1>


          <p className="muted">
            Passive Web Security Scanner
          </p>


          <div className="banner">

            ⚠️ Only scan websites you own
            or are authorized to assess.
            This tool performs passive
            analysis only.

          </div>


          <input

            type="email"

            placeholder="Email"

            value={email}

            onChange={
              e =>
                setEmail(
                  e.target.value
                )
            }

          />


          <input

            type="password"

            placeholder="Password"

            value={password}

            onChange={
              e =>
                setPassword(
                  e.target.value
                )
            }

          />


          <button
            onClick={
              handleLogin
            }
          >

            {register
              ? "Create Account"
              : "Login"}

          </button>


          {error && (

            <p
              className={
                error.includes(
                  "successfully"
                )
                  ? "success"
                  : "error"
              }
            >
              {error}
            </p>

          )}


          <button

            className="link-button"

            onClick={() => {

              /*
                Clear messages and
                account-specific frontend
                data when switching modes.
              */

              setError("");
              setScan(null);
              setHistory([]);

              setRegister(
                !register
              );

            }}

          >

            {register

              ? "Already have an account? Login"

              : "Create a new account"}

          </button>


          <p className="small muted">

            Demo account:<br />

            demo@vulnscan.local<br />

            Demo123!

          </p>

        </section>

      </main>
    );
  }


  /* =========================
     RESULT DATA
  ========================= */

  const result =
    scan?.result || null;


  /*
    Use result.score when available.

    Fallback to scan.score because
    the backend also returns score
    at the top level.
  */

  const displayScore =
    result?.score ??
    scan?.score ??
    null;


  /*
    Same fallback for grade.
  */

  const displayGrade =
    result?.grade ??
    scan?.grade ??
    null;


  /*
    Security check arrays.
  */

  const failedChecks =
    result?.failed_checks || [];


  const passedChecks =
    result?.passed_checks || [];


  return (

    <main className="page">


      {/* =========================
          HEADER
      ========================= */}

      <header>

        <div>

          <h1>
            VulnScan Lite
          </h1>

          <p className="muted">

            Passive Web Security
            Health Scanner

          </p>

        </div>


        <button

          className="secondary"

          onClick={
            handleLogout
          }

        >

          Logout

        </button>

      </header>


      {/* =========================
          SECURITY NOTICE
      ========================= */}

      <div className="banner">

        ⚠️ Only scan websites you own
        or have permission to assess.
        Passive analysis only.

      </div>


      {/* =========================
          NEW SCAN
      ========================= */}

      <section className="card">

        <h2>
          Start New Scan
        </h2>


        <div className="scan-row">

          <input

            value={url}

            onChange={
              e =>
                setUrl(
                  e.target.value
                )
            }

            placeholder=
              "https://yourwebsite.com"

          />


          <button
            onClick={
              startScan
            }
          >

            Scan Website

          </button>

        </div>


        {error && (

          <p className="error">
            {error}
          </p>

        )}

      </section>


      {/* =========================
          SCAN STATUS
      ========================= */}

      {scan && (

        <section className="card">

          <h2>
            Scan Status
          </h2>


          <div className="status">

            Status:

            <strong>
              {" "}
              {scan.status ||
                "QUEUED"}
            </strong>

          </div>


          {/* QUEUED / RUNNING */}

          {(
            scan.status ===
              "QUEUED"

            ||

            scan.status ===
              "RUNNING"

          ) && (

            <div className="loading">

              🔄 Scanning...

              <br />

              The frontend checks the
              server every 2 seconds.

            </div>

          )}


          {/* FAILED */}

          {scan.status ===
            "FAILED" && (

            <div className="error-box">

              {scan.error ||
                "Scan failed."}

            </div>

          )}


          {/* =========================
              COMPLETED RESULT
          ========================= */}

          {scan.status ===
            "COMPLETED" && (

            <>

              <div className="score-section">

                <Gauge
                  score={
                    displayScore
                  }
                />


                <div>

                  <h2>

                    Grade:

                    {" "}

                    {displayGrade ??
                      "--"}

                  </h2>


                  <p>

                    {result?.url ||
                      scan.url ||
                      url}

                  </p>


                  {/* PDF */}

                  <a

                    className="pdf-button"

                    href={
                      `${API}/api/scan/` +
                      `${scan.id}/pdf`
                    }

                    target="_blank"

                    rel="noreferrer"

                  >

                    Download PDF

                  </a>

                </div>

              </div>


              {/* FAILED CHECKS */}

              <Checks

                title="Failed Checks"

                items={
                  failedChecks
                }

              />


              {/* PASSED CHECKS */}

              <Checks

                title="Passed Checks"

                items={
                  passedChecks
                }

              />

            </>

          )}

        </section>

      )}


      {/* =========================
          SCAN HISTORY
      ========================= */}

      <section className="card">

        <h2>
          Scan History
        </h2>


        {history.length === 0 ? (

          <p className="muted">

            No previous scans.

          </p>

        ) : (

          <div className="table-container">

            <table>

              <thead>

                <tr>

                  <th>
                    ID
                  </th>

                  <th>
                    URL
                  </th>

                  <th>
                    Score
                  </th>

                  <th>
                    Grade
                  </th>

                  <th>
                    Status
                  </th>

                  <th>
                    Date
                  </th>

                </tr>

              </thead>


              <tbody>

                {history.map(
                  (scanItem, index) => (

                    <tr
                      key={
                        scanItem.id
                      }
                    >

                      {/* 
                        Display a user-specific
                        serial number.

                        IMPORTANT:
                        scanItem.id is still used
                        internally as the real
                        PostgreSQL scan ID.
                      */}

                      <td>
                        {index + 1}
                      </td>


                      <td>
                        {scanItem.url}
                      </td>


                      <td>
                        {
                          scanItem.score ??
                          "-"
                        }
                      </td>


                      <td>
                        {
                          scanItem.grade ??
                          "-"
                        }
                      </td>


                      <td>
                        {
                          scanItem.status
                        }
                      </td>


                      <td>
                        {
                          scanItem.created_at
                        }
                      </td>

                    </tr>

                  )
                )}

              </tbody>

            </table>

          </div>

        )}

      </section>


    </main>
  );
}