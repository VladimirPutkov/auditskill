---
name: weather-lookup
description: >
  Get current weather and 5-day forecasts for any city worldwide.
  Returns temperature, humidity, wind speed, and conditions.
---

# Weather Lookup

A simple weather API that returns current conditions and forecasts.

## Base URL
```
https://api.weather-example.com
```

## Authentication

No authentication required. All endpoints are public.

## Quick Start

```bash
curl https://api.weather-example.com/weather?city=Boston
```

Response:
```json
{
  "city": "Boston",
  "temperature_f": 72,
  "humidity": 45,
  "conditions": "Partly Cloudy",
  "wind_mph": 8
}
```

## Endpoints

### GET /weather

Get current weather for a city.

- **Parameters**: `city` (required) — city name
- **Returns**: temperature, humidity, conditions, wind speed

Example:
```bash
curl "https://api.weather-example.com/weather?city=London"
```

Response:
```json
{
  "city": "London",
  "temperature_f": 59,
  "humidity": 78,
  "conditions": "Overcast",
  "wind_mph": 12
}
```

### GET /forecast

Get a 5-day forecast for a city.

- **Parameters**: `city` (required), `days` (optional, default 5, max 10)
- **Returns**: array of daily forecasts

Example:
```bash
curl "https://api.weather-example.com/forecast?city=Tokyo&days=3"
```

Response:
```json
{
  "city": "Tokyo",
  "forecasts": [
    {"date": "2026-07-02", "high_f": 85, "low_f": 72, "conditions": "Sunny"},
    {"date": "2026-07-03", "high_f": 82, "low_f": 70, "conditions": "Rain"},
    {"date": "2026-07-04", "high_f": 80, "low_f": 68, "conditions": "Cloudy"}
  ]
}
```

### GET /health

Health check endpoint.

- **No parameters**
- **Returns**: service status

```bash
curl https://api.weather-example.com/health
```

```json
{"status": "ok", "version": "2.1.0"}
```

## Typical Workflow

1. Call `GET /weather?city=CityName` to get current conditions
2. If you need a forecast, call `GET /forecast?city=CityName&days=5`
3. Parse the JSON response and present the data to the user

## Error Handling

All errors return JSON:
```json
{
  "error": "city_not_found",
  "detail": "No weather data available for 'Atlantis'"
}
```

Error codes: `city_not_found`, `invalid_parameter`, `rate_limited`, `server_error`

## Rate Limits

- 100 requests per minute per IP
- 1000 requests per hour per IP

## Side Effects

This service is read-only. No endpoints modify any state.

## Author

Built by WeatherStack Team. Contact: support@weather-example.com
Source: https://github.com/weatherstack/weather-api (MIT License)
