# Payrails SDK Demo

A simple Go backend demo for integrating the **Payrails Web SDK** using Gin.  
Includes **mTLS support**, **bearer token authentication**, and a **static client key** for secure requests.

---

## Requirements

- Go **1.18+**
- Payrails credentials
- `.env` file with:

```env
PAYRAILS_CLIENT_ID=your_client_id
PAYRAILS_API_KEY=your_api_key
PAYRAILS_BASE_URL=https://api.payrails.com
MTLS_CLIENT_CERT=base64_encoded_cert
MTLS_CLIENT_KEY=base64_encoded_key
CLIENT_KEY=static_client_key
PORT=5000
```

---

## Setup & Run

Clone the repository:

```bash
git clone https://github.com/luizdcastro/payrails-go-demo.git
cd payrails-go-demo
```

Install dependencies:

```bash
go mod tidy
```

Start the server:

```bash
go run main.go
```

Server runs on **PORT** (default: `5000`).

---

## API Endpoint

### `POST /payrails/sdk`

Initializes the Payrails SDK and returns configuration for the frontend.

**Headers required:**

```http
x-client-key: <CLIENT_KEY>
```

**Response Example:**

```json
{
  "status": "success",
  "data": {
    /* Payrails SDK configuration */
  }
}
```

---

## Notes

- CORS is configured to allow all origins and `x-client-key`.
- mTLS secures requests to Payrails API.
- Bearer token is cached and refreshed automatically.
