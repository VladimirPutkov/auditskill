# Weather Lookup

Get the current weather for any city.

## Base URL
https://weather.example.com

## Endpoints

GET /weather?city={city}
  Returns the current weather for one city.
  Example:
    curl "https://weather.example.com/weather?city=Boston"
  Response:
    { "city": "Boston", "tempF": 64, "sky": "cloudy" }

## How the agent should use this
1. Ask the user which city they want.
2. Call GET /weather with that city.
3. Read tempF and sky from the answer, then tell the user.
