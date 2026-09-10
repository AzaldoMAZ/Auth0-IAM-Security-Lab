import { useState } from "react";
import { useAuth0 } from "@auth0/auth0-react";
import "./App.css";

function App() {
  const {
    loginWithRedirect,
    logout,
    user,
    isAuthenticated,
    isLoading,
    getAccessTokenSilently,
  } = useAuth0();

  const [apiResponse, setApiResponse] = useState(null);
  const [apiError, setApiError] = useState("");
  const [isCallingApi, setIsCallingApi] = useState(false);

  const requestSensitiveMfa = async () => {
    setApiResponse(null);
    setApiError("");

    await loginWithRedirect({
      authorizationParams: {
        audience: import.meta.env.VITE_AUTH0_AUDIENCE,
        scope:
          "openid profile email read:protected read:sensitive",
        acr_values:
          "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
      },
      appState: {
        returnTo: window.location.pathname,
      },
    });
  };

  const callProtectedApi = async () => {
    setIsCallingApi(true);
    setApiResponse(null);
    setApiError("");

    try {
      const accessToken = await getAccessTokenSilently({
        authorizationParams: {
          audience: import.meta.env.VITE_AUTH0_AUDIENCE,
          scope: "read:protected",
        },
      });

      const response = await fetch(
        `${import.meta.env.VITE_API_URL}/api/protected`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "The protected API request failed."
        );
      }

      setApiResponse(data);
    } catch (error) {
      setApiError(error.message);
    } finally {
      setIsCallingApi(false);
    }
  };

  const callSensitiveApi = async () => {
    setIsCallingApi(true);
    setApiResponse(null);
    setApiError("");

    try {
      const accessToken = await getAccessTokenSilently({
        authorizationParams: {
          audience: import.meta.env.VITE_AUTH0_AUDIENCE,
          scope: "read:protected read:sensitive",
        },
      });

      const response = await fetch(
        `${import.meta.env.VITE_API_URL}/api/sensitive`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Complete MFA verification before calling this endpoint."
        );
      }

      setApiResponse(data);
    } catch (error) {
      setApiError(error.message);
    } finally {
      setIsCallingApi(false);
    }
  };

  if (isLoading) {
    return (
      <main className="page">
        <section className="card">
          <p className="description">Loading authentication...</p>
        </section>
      </main>
    );
  }

  return (
    <main className="page">
      <section className="card">
        <p className="eyebrow">
          PART 4 · STEP-UP MFA · REACT + FASTAPI
        </p>

        <h1>Identity Access Portal</h1>

        <p className="description">
          Sign in through Auth0, call the protected API and use
          step-up MFA before accessing sensitive information.
        </p>

        {!isAuthenticated ? (
          <button onClick={() => loginWithRedirect()}>
            Log in with Auth0
          </button>
        ) : (
          <>
            <div className="profile">
              {user?.picture ? (
                <img
                  src={user.picture}
                  alt={user.name || "Authenticated user"}
                />
              ) : (
                <div className="avatar">
                  {user?.name?.charAt(0) || "U"}
                </div>
              )}

              <div>
                <span>AUTHENTICATED USER</span>
                <strong>{user?.name}</strong>
                <p>{user?.email}</p>
              </div>
            </div>

            <div className="actions">
              <button
                onClick={callProtectedApi}
                disabled={isCallingApi}
              >
                {isCallingApi
                  ? "Calling API..."
                  : "Call Protected API"}
              </button>

              <button
                onClick={requestSensitiveMfa}
                disabled={isCallingApi}
              >
                Verify with MFA
              </button>

              <button
                onClick={callSensitiveApi}
                disabled={isCallingApi}
              >
                Call Sensitive API
              </button>

              <button
                className="secondary"
                onClick={() =>
                  logout({
                    logoutParams: {
                      returnTo: window.location.origin,
                    },
                  })
                }
              >
                Log out
              </button>
            </div>
          </>
        )}

        {apiResponse && (
          <div className="result success">
            <h2>Access granted</h2>
            <pre>{JSON.stringify(apiResponse, null, 2)}</pre>
          </div>
        )}

        {apiError && (
          <div className="result error">
            <h2>Access denied</h2>
            <p>{apiError}</p>
          </div>
        )}
      </section>
    </main>
  );
}

export default App;