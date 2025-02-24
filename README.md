# httpatch

## What is this?

`httpatch` is a simple tool to intercept HTTP traffic using `mitmproxy`, apply custom modifications to the responses, and handle them in real-time. It allows you to define rules that specify which requests to modify and how to change their JSON responses. Please note that I'm not sure if this works on Windows too, since I run Arch Linux and do not own a Windows.

## Features

- **Intercept HTTP traffic**: Runs `mitmproxy` on a specified port and intercepts the HTTP traffic.
- **Modify JSON responses**: Apply custom modifications to the JSON data in the response, based on user-defined rules.
- **Add, edit, and remove rules**: You can easily add, edit, or remove rules using the GUI.
- **Control mitmproxy**: Start or stop the proxy server with a simple button click.

## Installation
```bash
git clone https://github.com/hankdh/httpatch.git
cd httpatch
pip install -r requirements.txt
```
## Usage

1. Launch the app using:

   ```bash
   python app.py
   ```

2. Define the rules for modifying HTTP responses:
   - **URL (regex)**: The URL pattern to match.
   - **JSON Path**: The path inside the JSON data where you want to apply changes.
   - **Replace With**: The value to replace the matched data with.

3. Click **Start Listening** to start the proxy server. Make sure to route your traffic through the specified port.

4. Click **Add New Rule** to add rules for modifying responses.

5. Double-click a rule in the list to edit it.

## To do list
- [ ] Add XML support
- [ ] Be able to change request body (payload) aswell
- [ ] Automatically change proxy settings when starting/running
