exports.onExecutePostLogin = async (event, api) => {
  const requestedValues = event.transaction?.acr_values ?? [];
  const acrValues = Array.isArray(requestedValues)
    ? requestedValues
    : [requestedValues];

  const mfaRequested = acrValues.includes(
    "http://schemas.openid.net/pape/policies/2007/06/multi-factor"
  );

  if (mfaRequested) {
    api.multifactor.enable("any", {
      allowRememberBrowser: false,
    });

    api.accessToken.setCustomClaim(
      "https://auth0-fastapi-lab/mfa",
      true
    );
  }
};
