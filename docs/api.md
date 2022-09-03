## General
This is the documentation of the Vulnerability-Info-API.
Vulnerability-Info-API receives vulnerability related notification from the DFN-CERT and scans it for CVEs. If CVEs are present more information about the vulnerabilities will be fetched and saved in association with the notification that supplied the information. If the provided notification does not contain any CVEs it will be saved anyway but no further information will be generated but the notification will also be available.

On a regular basis, all saved notifications that came with CVE information will be compared with the stored components via CPE identifier. If one of the components is affected by a provided information, they will also get associated and these relations will be made available through this API.

The basic workflow is described in the following, but it's recommended to use an UI (WIP) based on this API.

## Basic Workflow

### 1. Create an account
Create an Account an sign up at `/auth/signup`

### 2. Login
Login with your freshly created account under `auth/login`
You will receive a token to authorize your further requests. Use it in the request header like this:  `Authorization: Bearer <token>`

### 4. Search or Add your components
Search for exiting components via `/components/search` or create new ones:
1. Search for stored Vendors at `/vendors/search` or create them at `vendors`.
2. Create new components at `/components` with the previous given `vendorID`. Please make sure to set a proper CPE. It's recommended to get them form the official [CPE Dictionary](https://nvd.nist.gov/products/cpe/search))

### 5. Subscribe to your components
Subscribe to the components you like to monitor via  `/components/{id}/subscribe?user=example@domain.com`

### 6. Check for notifications
Regularly check for notifications that address you and your components at `/notifications?for=example@domain.com` or browse all stored notifications at `/notifications`
