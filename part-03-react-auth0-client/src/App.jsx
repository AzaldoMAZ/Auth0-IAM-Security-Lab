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
        },
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || `API request failed with status ${response.status}`,
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
    return <main className="page">Loading authentication...</main>;
  }

  return (
    <main className="page">
      <section className="card">
        <p className="eyebrow">PART 3 · AUTH0 + REACT + FASTAPI</p>
        <h1>Identity Access Portal</h1>
        <p className="description">
          Sign in through Auth0 and use your access token to call the
          permission-protected FastAPI endpoint.
        </p>

        {!isAuthenticated ? (
          <button className="primary" onClick={() => loginWithRedirect()}>
            Log in with Auth0
          </button>
        ) : (
          <>
            <div className="profile">
              {user?.picture && (
                <img src={user.picture} alt={user.name || "User profile"} />
              )}

              <div>
                <span>Authenticated user</span>
                <strong>{user?.name}</strong>
                <p>{user?.email}</p>
              </div>
            </div>

            <div className="actions">
              <button
                className="primary"
                onClick={callProtectedApi}
                disabled={isCallingApi}
              >
                {isCallingApi ? "Calling API..." : "Call Protected API"}
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
            <h2>Request failed</h2>
            <p>{apiError}</p>
          </div>
        )}
      </section>
    </main>
  );
}

export default App;