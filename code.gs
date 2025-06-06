const CLIENT_ID = 'ownerapi';
const REDIRECT_URI = 'https://auth.tesla.com/void/callback';
const AUTH_URL = 'https://auth.tesla.com/oauth2/v3/authorize';
const TOKEN_URL = 'https://auth.tesla.com/oauth2/v3/token';
const SCOPE = 'openid email offline_access';
const CODE_CHALLENGE_METHOD = 'S256';
const APP_VERSION = '4.44.5-3304';
const TOKEN_KEY = 'tesla_tokens';
const ORDERS_FILE_NAME = 'tesla_orders.json';

function doGet() {
  return HtmlService.createHtmlOutputFromFile('index')
    .setTitle('Tesla Order Status Bot');
}

function startAuthentication() {
  Logger.log("startAuthentication fonksiyonu çağrıldı!");
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  PropertiesService.getScriptProperties().setProperty('code_verifier', codeVerifier);
  
  const authParams = {
    'client_id': CLIENT_ID,
    'redirect_uri': REDIRECT_URI,
    'response_type': 'code',
    'scope': SCOPE,
    'state': Utilities.getUuid(),
    'code_challenge': codeChallenge,
    'code_challenge_method': CODE_CHALLENGE_METHOD
  };
  const authUrl = `${AUTH_URL}?${Object.keys(authParams).map(k => `${k}=${encodeURIComponent(authParams[k])}`).join('&')}`;
  Logger.log("Oluşturulan authUrl: " + authUrl);
  return { authUrl };
}

function generateCodeVerifier() {
  const randomBytes = Utilities.getUuid().replace(/-/g, '');
  return Utilities.base64Encode(randomBytes).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function generateCodeChallenge(verifier) {
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, verifier);
  return Utilities.base64Encode(digest).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function exchangeCodeForTokens(codeInput) {
  Logger.log("exchangeCodeForTokens çağrıldı, codeInput: " + codeInput);
  let authCode = codeInput;
  
  if (codeInput.includes('code=')) {
    const queryString = codeInput.split('?')[1];
    const params = queryString.split('&').reduce((acc, param) => {
      const [key, value] = param.split('=');
      acc[key] = value;
      return acc;
    }, {});
    authCode = params.code;
  }
  
  const codeVerifier = PropertiesService.getScriptProperties().getProperty('code_verifier');
  const tokenData = {
    'grant_type': 'authorization_code',
    'client_id': CLIENT_ID,
    'code': authCode,
    'redirect_uri': REDIRECT_URI,
    'code_verifier': codeVerifier
  };
  
  const response = UrlFetchApp.fetch(TOKEN_URL, {
    method: 'post',
    payload: tokenData,
    muteHttpExceptions: true
  });
  
  if (response.getResponseCode() !== 200) {
    Logger.log("Token alma hatası: " + response.getContentText());
    throw new Error("Token alma başarısız: " + response.getContentText());
  }
  
  const tokens = JSON.parse(response.getContentText());
  PropertiesService.getScriptProperties().setProperty(TOKEN_KEY, JSON.stringify(tokens));
  Logger.log("Tokens alındı: " + JSON.stringify(tokens));
  return retrieveOrders();
}

function refreshTokens(refreshToken) {
  Logger.log("refreshTokens çağrıldı, refreshToken: " + refreshToken);
  const tokenData = {
    'grant_type': 'refresh_token',
    'client_id': CLIENT_ID,
    'refresh_token': refreshToken
  };
  const response = UrlFetchApp.fetch(TOKEN_URL, {
    method: 'post',
    payload: tokenData,
    muteHttpExceptions: true
  });
  
  if (response.getResponseCode() !== 200) {
    Logger.log("Token yenileme hatası: " + response.getContentText());
    throw new Error("Token yenileme başarısız: " + response.getContentText());
  }
  
  const tokens = JSON.parse(response.getContentText());
  PropertiesService.getScriptProperties().setProperty(TOKEN_KEY, JSON.stringify(tokens));
  Logger.log("Yeni tokens alındı: " + JSON.stringify(tokens));
  return tokens.access_token;
}

function isTokenValid(accessToken) {
  try {
    const payload = JSON.parse(Utilities.base64Decode(accessToken.split('.')[1] + '=='));
    return payload.exp > Math.floor(Date.now() / 1000);
  } catch (e) {
    Logger.log("Token geçerlilik kontrolü hatası: " + e);
    return false;
  }
}

function retrieveOrders() {
  Logger.log("retrieveOrders çağrıldı!");
  let tokens = JSON.parse(PropertiesService.getScriptProperties().getProperty(TOKEN_KEY));
  let accessToken = tokens.access_token;
  
  if (!isTokenValid(accessToken)) {
    Logger.log("Token geçersiz, yenileniyor...");
    accessToken = refreshTokens(tokens.refresh_token);
  }
  
  const headers = { 'Authorization': `Bearer ${accessToken}` };
  const ordersResponse = UrlFetchApp.fetch('https://owner-api.teslamotors.com/api/1/users/orders', { headers });
  
  if (ordersResponse.getResponseCode() !== 200) {
    Logger.log("Sipariş alma hatası: " + ordersResponse.getContentText());
    throw new Error("Sipariş alma başarısız: " + ordersResponse.getContentText());
  }
  
  const orders = JSON.parse(ordersResponse.getContentText()).response;
  Logger.log("Siparişler alındı: " + JSON.stringify(orders));
  
  const detailedOrders = orders.map(order => {
    const orderDetails = getOrderDetails(order.referenceNumber, accessToken);
    return { order, details: orderDetails };
  });
  
  saveOrdersToFile(detailedOrders);
  return detailedOrders;
}

function getOrderDetails(orderId, accessToken) {
  Logger.log("getOrderDetails çağrıldı, orderId: " + orderId);
  const headers = { 'Authorization': `Bearer ${accessToken}` };
  const url = `https://akamai-apigateway-vfx.tesla.com/tasks?deviceLanguage=en&deviceCountry=DE&referenceNumber=${orderId}&appVersion=${APP_VERSION}`;
  const response = UrlFetchApp.fetch(url, { headers });
  
  if (response.getResponseCode() !== 200) {
    Logger.log("Sipariş detayları alma hatası: " + response.getContentText());
    throw new Error("Sipariş detayları alma başarısız: " + response.getContentText());
  }
  
  const details = JSON.parse(response.getContentText());
  
  // JSON'u parçalara bölerek logla
  const jsonString = JSON.stringify(details, null, 2);
  const maxLength = 1000; // Her log girişi için maksimum uzunluk
  for (let i = 0; i < jsonString.length; i += maxLength) {
    Logger.log(`JSON Parça ${i / maxLength + 1}: ${jsonString.slice(i, i + maxLength)}`);
  }
  
  return details;
}

function saveOrdersToFile(orders) {
  Logger.log("saveOrdersToFile çağrıldı!");
  const file = DriveApp.getFilesByName(ORDERS_FILE_NAME).hasNext()
    ? DriveApp.getFilesByName(ORDERS_FILE_NAME).next()
    : DriveApp.createFile(ORDERS_FILE_NAME, JSON.stringify(orders), 'application/json');
  file.setContent(JSON.stringify(orders));
  Logger.log("Siparişler dosyaya kaydedildi.");
}
