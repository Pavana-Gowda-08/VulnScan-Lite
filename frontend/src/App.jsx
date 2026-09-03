import React, {
  useEffect,
  useState
} from "react";


const API="http://localhost:5000";


async function api(
  endpoint,
  options = {}
) {

  const response = await fetch(

    API + endpoint,

    {
      credentials: "include",

      headers: {
        "Content-Type":
          "application/json",

        ...(options.headers || {})
      },

      ...options
    }
  );


  const data =
    await response
      .json()
      .catch(
        () => ({})
      );


  if (!response.ok) {

    throw new Error(
      data.error
      || "Request failed"
    );
  }


  return data;
}


function Gauge({
  score
}) {

  return (

    <div
      className="gauge"
      style={{
        "--score":
          score || 0
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


function Checks({
  title,
  items
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
              key={index}
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


  async function loadHistory() {

    try {

      const data =
        await api(
          "/api/history"
        );

      setHistory(
        data.scans
      );

    } catch {

      // User may not be logged in.
    }
  }


  async function handleLogin() {

    setError("");

    try {

      const data =
        await api(

          register
            ? "/api/auth/register"
            : "/api/auth/login",

          {
            method: "POST",

            body: JSON.stringify({

              email,
              password

            })
          }
        );


      setUser(
        data.user
      );

      loadHistory();

    } catch (error) {

      setError(
        error.message
      );
    }
  }


  async function handleLogout() {

    await api(
      "/api/auth/logout",
      {
        method: "POST"
      }
    );

    setUser(null);

    setScan(null);
  }


  async function startScan() {

    setError("");

    setScan({

      status:
        "QUEUED"
    });


    try {

      const data =
        await api(

          "/api/scan",

          {

            method:
              "POST",

            body:
              JSON.stringify({
                url
              })
          }
        );


      setScan({

        id:
          data.scan_id,

        status:
          "QUEUED"
      });

    } catch (error) {

      setError(
        error.message
      );

      setScan(null);
    }
  }


  useEffect(
    () => {

      if (!scan?.id) {
        return;
      }


      const interval =
        setInterval(
          async () => {

            try {

              const data =
                await api(

                  `/api/scan/${scan.id}/status`
                );


              setScan(
                data
              );


              if (

                data.status
                === "COMPLETED"

                ||

                data.status
                === "FAILED"

              ) {

                clearInterval(
                  interval
                );

                loadHistory();
              }

            } catch (error) {

              setError(
                error.message
              );

              clearInterval(
                interval
              );
            }

          },

          2000
        );


      return () =>
        clearInterval(
          interval
        );

    },

    [scan?.id]
  );


  if (!user) {

    return (

      <main className="auth">

        <section className="card auth-card">

          <h1>
            VulnScan Lite
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

            <p className="error">
              {error}
            </p>

          )}


          <button

            className="link-button"

            onClick={() =>
              setRegister(
                !register
              )
            }

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


  const result =
    scan?.result;


  return (

    <main className="page">

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


      <div className="banner">

        ⚠️ Only scan websites you own
        or have permission to assess.
        Passive analysis only.

      </div>


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


      {scan && (

        <section className="card">

          <h2>
            Scan Status
          </h2>


          <div className="status">

            Status:

            <strong>
              {" "}{scan.status}
            </strong>

          </div>


          {(scan.status === "QUEUED"
            || scan.status === "RUNNING") && (

            <div className="loading">

              🔄 Scanning...

              <br />

              The frontend checks the
              server every 2 seconds.

            </div>

          )}


          {scan.status === "FAILED" && (

            <div className="error-box">

              {scan.error}

            </div>

          )}


          {result && (

            <>

              <div className="score-section">

                <Gauge
                  score={
                    result.score
                  }
                />


                <div>

                  <h2>

                    Grade:
                    {" "}
                    {result.grade}

                  </h2>

                  <p>
                    {result.url}
                  </p>


                  <a

                    className="pdf-button"

                    href={
                      `${API}/api/scan/`
                      + `${scan.id}/pdf`
                    }

                    target="_blank"

                    rel="noreferrer"

                  >

                    Download PDF

                  </a>

                </div>

              </div>


              <Checks

                title="Failed Checks"

                items={
                  result.failed_checks
                }

              />


              <Checks

                title="Passed Checks"

                items={
                  result.passed_checks
                }

              />

            </>

          )}

        </section>

      )}


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

                  <th>ID</th>

                  <th>URL</th>

                  <th>Score</th>

                  <th>Grade</th>

                  <th>Status</th>

                  <th>Date</th>

                </tr>

              </thead>


              <tbody>

                {history.map(
                  scan => (

                    <tr
                      key={
                        scan.id
                      }
                    >

                      <td>
                        {scan.id}
                      </td>

                      <td>
                        {scan.url}
                      </td>

                      <td>
                        {scan.score ?? "-"}
                      </td>

                      <td>
                        {scan.grade ?? "-"}
                      </td>

                      <td>
                        {scan.status}
                      </td>

                      <td>
                        {scan.created_at}
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