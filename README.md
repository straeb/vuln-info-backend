# Vuln-Info-Backend
Vulnerability-Info-Backend receives vulnerability related notification from the DFN-CERT and scans it for CVEs. If CVEs are present more information about the vulnerabilities will be fetched and saved in association with the notification that supplied the information. If the provided notification does not contain any CVEs it will be saved anyway but no further information will be generated but the notification will also be available.

On a regular basis, all saved notifications that came with CVE information will be compared with the stored components via CPE identifier. If one of the components is affected by a provided information, they will also get associated and these relations will be made available through API.

## Installation
### 1. Provide all necessary information in a `.env` file

Best is to use the `CHANGEME.env` template. In there are are 3 blocks of cron-configs. These control the periodical matching between stored components and gathered vulnerability information. Newly provided information in CVE records will decrease over time, so it's not necessary to update old entries every day. If only two or less jobs are needed, set the others to `'0 0 31 2 *'` which is the 31th of February and will never be executed.
````yml
CRON_STRING_n='* 3 * * *' # -> UNIX like time schedule:  = every day at 03:00AM
FROM_DAYS_n='0' # -> From today...
TO_DAYS_n='-10' # -> ...to 10 days in the past
````
It's also necessary to provide a link to the DFN-RSS feed that should be requested. You'll find another cron variable for this job. Generally speaking, all listed variables in `CHANGEME.env` are required.

### 2. Build an Docker image
Either run the Dockerfile manually or just run `$ docker-compose up`, which will do all the work. It will start a mySQL Database and the service itself. Database will be migrated independently.

## API
Once both services are up and running the endpoints of the REST-API are reachable at `<base>:8080/api/v1/`. These are described in greater detail in the Swagger documentation reachable at `<base>:8080/docs/index.html`.

## Basic Workflow

### 1. Create an account
Create an Account an sign up at `/auth/signup`

### 2. Login
Login with your freshly created account under `auth/login`
You will receive a token to authorize your further requests. Use it in the request header like   `Authorization: Bearer <token>`

### 4. Search or Add your components
Search for exiting components via `/components/search` or create new ones:
1. Search for stored Vendors at `/vendors/search` or create them at `vendors`.
2. Create new components at `/components` with the previous given `vendorID`. Please make sure to set a proper CPE. It's recommended to get them form the official [CPE Dictionary](https://nvd.nist.gov/products/cpe/search))

### 5. Subscribe to your components
Subscribe to the components you like to monitor via  `/components/{id}/subscribe?user=example@domain.com`

### 6. Check for notifications
Regularly check for notifications that address you and your components at `/notifications?for=example@domain.com` or browse all stored notifications at `/notifications`

## Further Work
- **Frontend**: Development of a GUI is planed, to make this more useful.
- **Authorization**: Authorization is pretty basic by now. It's mainly used to provide information for particular users. However, switching to a more complex authorization method not useful until a GUI is given.
