<?php
/**
 * Plugin Name: Luna Chat — Widget (Client)
 * Description: Floating chat widget + shortcode with conversation logging. Pulls client facts from Visible Light Hub and blends them with AI answers. Includes chat history hydration and Hub-gated REST endpoints.
 * Version:     1.6.0
 * Author:      Visible Light
 * License:     GPLv2 or later
 */

if (!defined('ABSPATH')) exit;

/* ============================================================
 * CONSTANTS & OPTIONS
 * ============================================================ */
if (!defined('LUNA_WIDGET_PLUGIN_VERSION')) define('LUNA_WIDGET_PLUGIN_VERSION', '1.6.0');

define('LUNA_WIDGET_OPT_LICENSE',         'luna_widget_license');
define('LUNA_WIDGET_OPT_MODE',            'luna_widget_mode');           // 'shortcode' | 'widget'
define('LUNA_WIDGET_OPT_SETTINGS',        'luna_widget_ui_settings');    // array
define('LUNA_WIDGET_OPT_LICENSE_SERVER',  'luna_widget_license_server'); // hub base URL
define('LUNA_WIDGET_OPT_LAST_PING',       'luna_widget_last_ping');      // array {ts,url,code,err,body}

/* Cache */
define('LUNA_CACHE_PROFILE_TTL',          300); // 5 min

/* Hub endpoints map (your Hub can alias to these) */
$GLOBALS['LUNA_HUB_ENDPOINTS'] = array(
  'profile'  => '/wp-json/vl-hub/v1/profile',   // preferred single profile
  'security' => '/wp-json/vl-hub/v1/security',  // fallback piece
  'content'  => '/wp-json/vl-hub/v1/content',   // fallback piece
  'users'    => '/wp-json/vl-hub/v1/users',     // fallback piece
);

/* ============================================================
 * ACTIVATION / DEACTIVATION
 * ============================================================ */
register_activation_hook(__FILE__, function () {
  if (!get_option(LUNA_WIDGET_OPT_MODE, null)) {
    update_option(LUNA_WIDGET_OPT_MODE, 'widget');
  }
  if (!get_option(LUNA_WIDGET_OPT_SETTINGS, null)) {
    update_option(LUNA_WIDGET_OPT_SETTINGS, array(
      'position'    => 'bottom-right',
      'title'       => 'Luna Chat',
      'avatar_url'  => '',
      'header_text' => "Hi, I'm Luna",
      'sub_text'    => 'How can I help today?',
    ));
  }
  if (!get_option(LUNA_WIDGET_OPT_LICENSE_SERVER, null)) {
    update_option(LUNA_WIDGET_OPT_LICENSE_SERVER, 'https://visiblelight.ai');
  }
  if (!wp_next_scheduled('luna_widget_heartbeat_event')) {
    wp_schedule_event(time() + 60, 'hourly', 'luna_widget_heartbeat_event');
  }
});

register_deactivation_hook(__FILE__, function () {
  $ts = wp_next_scheduled('luna_widget_heartbeat_event');
  if ($ts) wp_unschedule_event($ts, 'luna_widget_heartbeat_event');
});

/* ============================================================
 * ADMIN MENU (Top-level)
 * ============================================================ */
add_action('admin_menu', function () {
  add_menu_page(
    'Luna Widget',
    'Luna Widget',
    'manage_options',
    'luna-widget',
    'luna_widget_admin_page',
    'dashicons-format-chat',
    64
  );
  add_submenu_page(
    'luna-widget',
    'Settings',
    'Settings',
    'manage_options',
    'luna-widget',
    'luna_widget_admin_page'
  );
  add_submenu_page(
    'luna-widget',
    'Security',
    'Security',
    'manage_options',
    'luna-widget-security',
    'luna_widget_security_admin_page'
  );
  add_submenu_page(
    'luna-widget',
    'Keywords',
    'Keywords',
    'manage_options',
    'luna-widget-keywords',
    'luna_widget_keywords_admin_page'
  );
  
  // Add JavaScript for keywords page
  add_action('admin_enqueue_scripts', function($hook) {
    if ($hook === 'luna-widget_page_luna-widget-keywords') {
      add_action('admin_footer', 'luna_keywords_admin_scripts');
    }
  });
  add_submenu_page(
    'luna-widget',
    'Analytics',
    'Analytics',
    'manage_options',
    'luna-widget-analytics',
    'luna_widget_analytics_admin_page'
  );
});

/* ============================================================
 * SETTINGS
 * ============================================================ */
add_action('admin_init', function () {
  register_setting('luna_widget_settings', LUNA_WIDGET_OPT_LICENSE, array(
    'type' => 'string',
    'sanitize_callback' => function($v){ return preg_replace('/[^A-Za-z0-9\-\_]/','', (string)$v); },
    'default' => '',
  ));
  register_setting('luna_widget_settings', 'luna_openai_api_key', array(
    'type' => 'string',
    'sanitize_callback' => function($v){ return trim((string)$v); },
    'default' => '',
  ));
  register_setting('luna_widget_settings', LUNA_WIDGET_OPT_LICENSE_SERVER, array(
    'type' => 'string',
    'sanitize_callback' => function($v){
      $v = trim((string)$v);
      if ($v === '') return 'https://visiblelight.ai';
      $v = preg_replace('#/+$#','',$v);
      $v = preg_replace('#^http://#i','https://',$v);
      return esc_url_raw($v);
    },
    'default' => 'https://visiblelight.ai',
  ));
  
  // Security settings
  register_setting('luna_widget_security', 'luna_security_overrides', array(
    'type' => 'array',
    'sanitize_callback' => 'luna_sanitize_security_overrides',
    'default' => array(),
  ));
  register_setting('luna_widget_settings', LUNA_WIDGET_OPT_MODE, array(
    'type' => 'string',
    'sanitize_callback' => function($v){ return in_array($v, array('shortcode','widget'), true) ? $v : 'widget'; },
    'default' => 'widget',
  ));
  register_setting('luna_widget_settings', LUNA_WIDGET_OPT_SETTINGS, array(
    'type' => 'array',
    'sanitize_callback' => function($a){
      $a = is_array($a) ? $a : array();
      $pos = isset($a['position']) ? strtolower((string)$a['position']) : 'bottom-right';
      $valid_positions = array('top-left','top-center','top-right','bottom-left','bottom-center','bottom-right');
      if (!in_array($pos, $valid_positions, true)) $pos = 'bottom-right';
      return array(
        'position'    => $pos,
        'title'       => sanitize_text_field(isset($a['title']) ? $a['title'] : 'Luna Chat'),
        'avatar_url'  => esc_url_raw(isset($a['avatar_url']) ? $a['avatar_url'] : ''),
        'header_text' => sanitize_text_field(isset($a['header_text']) ? $a['header_text'] : "Hi, I'm Luna"),
        'sub_text'    => sanitize_text_field(isset($a['sub_text']) ? $a['sub_text'] : 'How can I help today?'),
      );
    },
    'default' => array(),
  ));
});

/* Settings page */
function luna_widget_admin_page(){
  if (!current_user_can('manage_options')) return;
  $mode  = get_option(LUNA_WIDGET_OPT_MODE, 'widget');
  $ui    = get_option(LUNA_WIDGET_OPT_SETTINGS, array());
  $lic   = get_option(LUNA_WIDGET_OPT_LICENSE, '');
  $hub   = luna_widget_hub_base();
  $last  = get_option(LUNA_WIDGET_OPT_LAST_PING, array());
  ?>
  <div class="wrap">
    <h1>Luna Chat — Widget</h1>

    <div class="notice notice-info" style="padding:8px 12px;margin-top:10px;">
      <strong>Hub connection:</strong>
      <?php if (!empty($last['code'])): ?>
        Response <code><?php echo (int)$last['code']; ?></code> at <?php echo esc_html(isset($last['ts']) ? $last['ts'] : ''); ?>.
      <?php else: ?>
        No heartbeat recorded yet.
      <?php endif; ?>
      <div style="margin-top:6px;display:flex;gap:8px;align-items:center;">
        <button type="button" class="button" id="luna-test-activation">Test Activation</button>
        <button type="button" class="button" id="luna-test-heartbeat">Heartbeat Now</button>
        <span style="opacity:.8;">Hub: <?php echo esc_html($hub); ?></span>
      </div>
    </div>

    <form method="post" action="options.php">
      <?php settings_fields('luna_widget_settings'); ?>
      <table class="form-table" role="presentation">
        <tr>
          <th scope="row">Corporate License Code</th>
          <td>
            <input type="text" name="<?php echo esc_attr(LUNA_WIDGET_OPT_LICENSE); ?>" value="<?php echo esc_attr($lic); ?>" class="regular-text code" placeholder="VL-XXXX-XXXX-XXXX" />
            <p class="description">Required for secured Hub data.</p>
          </td>
        </tr>
        <tr>
          <th scope="row">License Server (Hub)</th>
          <td>
            <input type="url" name="<?php echo esc_attr(LUNA_WIDGET_OPT_LICENSE_SERVER); ?>" value="<?php echo esc_url($hub); ?>" class="regular-text code" placeholder="https://visiblelight.ai" />
            <p class="description">HTTPS enforced; trailing slashes removed automatically.</p>
          </td>
        </tr>
        <tr>
          <th scope="row">Embedding mode</th>
          <td>
            <label style="display:block;margin-bottom:.4rem;">
              <input type="radio" name="<?php echo esc_attr(LUNA_WIDGET_OPT_MODE); ?>" value="shortcode" <?php checked($mode, 'shortcode'); ?>>
              Shortcode only (<code>[luna_chat]</code>)
            </label>
            <label>
              <input type="radio" name="<?php echo esc_attr(LUNA_WIDGET_OPT_MODE); ?>" value="widget" <?php checked($mode, 'widget'); ?>>
              Floating chat widget (site-wide)
            </label>
          </td>
        </tr>
        <tr>
          <th scope="row">Widget UI</th>
          <td>
            <label style="display:block;margin:.25rem 0;">
              <span style="display:inline-block;width:140px;">Title</span>
              <input type="text" name="<?php echo esc_attr(LUNA_WIDGET_OPT_SETTINGS); ?>[title]" value="<?php echo esc_attr(isset($ui['title']) ? $ui['title'] : 'Luna Chat'); ?>" />
            </label>
            <label style="display:block;margin:.25rem 0;">
              <span style="display:inline-block;width:140px;">Avatar URL</span>
              <input type="url" name="<?php echo esc_attr(LUNA_WIDGET_OPT_SETTINGS); ?>[avatar_url]" value="<?php echo esc_url(isset($ui['avatar_url']) ? $ui['avatar_url'] : ''); ?>" class="regular-text code" placeholder="https://…/luna.png" />
            </label>
            <label style="display:block;margin:.25rem 0;">
              <span style="display:inline-block;width:140px;">Header text</span>
              <input type="text" name="<?php echo esc_attr(LUNA_WIDGET_OPT_SETTINGS); ?>[header_text]" value="<?php echo esc_attr(isset($ui['header_text']) ? $ui['header_text'] : "Hi, I'm Luna"); ?>" />
            </label>
            <label style="display:block;margin:.25rem 0;">
              <span style="display:inline-block;width:140px;">Sub text</span>
              <input type="text" name="<?php echo esc_attr(LUNA_WIDGET_OPT_SETTINGS); ?>[sub_text]" value="<?php echo esc_attr(isset($ui['sub_text']) ? $ui['sub_text'] : 'How can I help today?'); ?>" />
            </label>
            <label style="display:block;margin:.25rem 0;">
              <span style="display:inline-block;width:140px;">Position</span>
              <?php $pos = isset($ui['position']) ? $ui['position'] : 'bottom-right'; ?>
              <select name="<?php echo esc_attr(LUNA_WIDGET_OPT_SETTINGS); ?>[position]">
                <?php foreach (array('top-left','top-center','top-right','bottom-left','bottom-center','bottom-right') as $p): ?>
                  <option value="<?php echo esc_attr($p); ?>" <?php selected($p, $pos); ?>><?php echo esc_html($p); ?></option>
                <?php endforeach; ?>
              </select>
            </label>
          </td>
        </tr>
        <tr>
          <th scope="row">OpenAI API key</th>
          <td>
            <input type="password" name="luna_openai_api_key"
                   value="<?php echo esc_attr( get_option('luna_openai_api_key','') ); ?>"
                   class="regular-text code" placeholder="sk-..." />
            <p class="description">If present, AI answers are blended with Hub facts. Otherwise, deterministic replies only.</p>
          </td>
        </tr>
      </table>
      <?php submit_button('Save changes'); ?>
    </form>
  </div>

  <script>
    (function(){
      const nonce = '<?php echo wp_create_nonce('wp_rest'); ?>';
      async function call(path){
        try{ await fetch(path, {method:'POST', headers:{'X-WP-Nonce': nonce}}); location.reload(); }
        catch(e){ alert('Request failed. See console.'); console.error(e); }
      }
      document.addEventListener('click', function(e){
        if(e.target && e.target.id==='luna-test-activation'){ e.preventDefault(); call('<?php echo esc_url_raw( rest_url('luna_widget/v1/ping-hub') ); ?>'); }
        if(e.target && e.target.id==='luna-test-heartbeat'){ e.preventDefault(); call('<?php echo esc_url_raw( rest_url('luna_widget/v1/heartbeat-now') ); ?>'); }
      });
    })();
  </script>
  <?php
}

/* ============================================================
 * SECURITY ADMIN PAGE
 * ============================================================ */
function luna_widget_security_admin_page() {
  if (!current_user_can('manage_options')) return;

  // Save on post
  if ($_SERVER['REQUEST_METHOD'] === 'POST' && check_admin_referer('luna_widget_save_security')) {
    $in = array(
      'tls' => array(
        'valid'          => isset($_POST['tls_valid']) ? (bool)$_POST['tls_valid'] : null,
        'version'        => sanitize_text_field($_POST['tls_version'] ?? ''),
        'issuer'         => sanitize_text_field($_POST['tls_issuer'] ?? ''),
        'provider_guess' => sanitize_text_field($_POST['tls_provider_guess'] ?? ''),
        'valid_from'     => sanitize_text_field($_POST['tls_valid_from'] ?? ''),
        'valid_to'       => sanitize_text_field($_POST['tls_valid_to'] ?? ''),
        'days_remaining' => sanitize_text_field($_POST['tls_days_remaining'] ?? ''),
        'host'           => sanitize_text_field($_POST['tls_host'] ?? ''),
      ),
      'waf' => array(
        'provider'   => sanitize_text_field($_POST['waf_provider'] ?? ''),
        'last_audit' => sanitize_text_field($_POST['waf_last_audit'] ?? ''),
        'rulesets'   => sanitize_textarea_field($_POST['waf_rulesets'] ?? ''),
      ),
      'ids' => array(
        'provider'   => sanitize_text_field($_POST['ids_provider'] ?? ''),
        'last_scan'  => sanitize_text_field($_POST['ids_last_scan'] ?? ''),
        'result'     => sanitize_text_field($_POST['ids_result'] ?? ''),
        'schedule'   => sanitize_text_field($_POST['ids_schedule'] ?? ''),
      ),
      'auth' => array(
        'mfa'             => sanitize_text_field($_POST['auth_mfa'] ?? ''),
        'password_policy' => sanitize_text_field($_POST['auth_password_policy'] ?? ''),
        'session_timeout' => sanitize_text_field($_POST['auth_session_timeout'] ?? ''),
        'sso_providers'   => sanitize_text_field($_POST['auth_sso_providers'] ?? ''),
      ),
      'domain' => array(
        'domain'        => sanitize_text_field($_POST['domain_domain'] ?? ''),
        'registrar'     => sanitize_text_field($_POST['domain_registrar'] ?? ''),
        'registered_on' => sanitize_text_field($_POST['domain_registered_on'] ?? ''),
        'renewal_date'  => sanitize_text_field($_POST['domain_renewal_date'] ?? ''),
        'auto_renew'    => sanitize_text_field($_POST['domain_auto_renew'] ?? ''),
        'dns_records'   => wp_kses_post($_POST['domain_dns_records'] ?? ''),
      ),
    );
    update_option('luna_security_overrides', $in);
    
    // Send to Hub
    luna_send_security_to_hub($in);
    
    echo '<div class="updated"><p>Security data saved and sent to Visible Light Hub.</p></div>';
  }

  $ov = get_option('luna_security_overrides', array());
  ?>
  <div class="wrap">
    <h1>Luna Security</h1>
    <p>Enter your security information. This data will be sent to Visible Light Hub and used by Luna AI to answer security-related questions.</p>

    <form method="post" action="">
      <?php wp_nonce_field('luna_widget_save_security'); ?>

      <h2>TLS / SSL</h2>
      <table class="form-table" role="presentation">
        <tr><th scope="row">Valid</th><td><label><input type="checkbox" name="tls_valid" value="1" <?php checked(!empty($ov['tls']['valid'])); ?>> Site has a valid certificate</label></td></tr>
        <tr><th scope="row">TLS Version</th><td><input type="text" name="tls_version" class="regular-text" value="<?php echo esc_attr($ov['tls']['version'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Issuer</th><td><input type="text" name="tls_issuer" class="regular-text" value="<?php echo esc_attr($ov['tls']['issuer'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Provider (guess)</th><td><input type="text" name="tls_provider_guess" class="regular-text" value="<?php echo esc_attr($ov['tls']['provider_guess'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Valid From</th><td><input type="text" name="tls_valid_from" class="regular-text" value="<?php echo esc_attr($ov['tls']['valid_from'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Valid To</th><td><input type="text" name="tls_valid_to" class="regular-text" value="<?php echo esc_attr($ov['tls']['valid_to'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Days Remaining</th><td><input type="text" name="tls_days_remaining" class="regular-text" value="<?php echo esc_attr($ov['tls']['days_remaining'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Host</th><td><input type="text" name="tls_host" class="regular-text" value="<?php echo esc_attr($ov['tls']['host'] ?? ''); ?>"></td></tr>
      </table>

      <h2>Firewall / WAF</h2>
      <table class="form-table" role="presentation">
        <tr><th scope="row">Provider</th><td><input type="text" name="waf_provider" class="regular-text" value="<?php echo esc_attr($ov['waf']['provider'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Last Audit</th><td><input type="text" name="waf_last_audit" class="regular-text" value="<?php echo esc_attr($ov['waf']['last_audit'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Rulesets</th><td><textarea name="waf_rulesets" class="large-text" rows="3"><?php echo esc_textarea($ov['waf']['rulesets'] ?? ''); ?></textarea></td></tr>
      </table>

      <h2>Threat Detection / IDS</h2>
      <table class="form-table" role="presentation">
        <tr><th scope="row">Provider</th><td><input type="text" name="ids_provider" class="regular-text" value="<?php echo esc_attr($ov['ids']['provider'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Last Scan</th><td><input type="text" name="ids_last_scan" class="regular-text" value="<?php echo esc_attr($ov['ids']['last_scan'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Last Result</th><td><input type="text" name="ids_result" class="regular-text" value="<?php echo esc_attr($ov['ids']['result'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Scan Schedule</th><td><input type="text" name="ids_schedule" class="regular-text" value="<?php echo esc_attr($ov['ids']['schedule'] ?? ''); ?>"></td></tr>
      </table>

      <h2>Authentication</h2>
      <table class="form-table" role="presentation">
        <tr><th scope="row">MFA</th><td><input type="text" name="auth_mfa" class="regular-text" value="<?php echo esc_attr($ov['auth']['mfa'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Password Policy</th><td><input type="text" name="auth_password_policy" class="regular-text" value="<?php echo esc_attr($ov['auth']['password_policy'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Session Timeout</th><td><input type="text" name="auth_session_timeout" class="regular-text" value="<?php echo esc_attr($ov['auth']['session_timeout'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">SSO Providers</th><td><input type="text" name="auth_sso_providers" class="regular-text" value="<?php echo esc_attr($ov['auth']['sso_providers'] ?? ''); ?>"></td></tr>
      </table>

      <h2>Domain</h2>
      <table class="form-table" role="presentation">
        <tr><th scope="row">Domain</th><td><input type="text" name="domain_domain" class="regular-text" value="<?php echo esc_attr($ov['domain']['domain'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Registrar</th><td><input type="text" name="domain_registrar" class="regular-text" value="<?php echo esc_attr($ov['domain']['registrar'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Registered On</th><td><input type="text" name="domain_registered_on" class="regular-text" value="<?php echo esc_attr($ov['domain']['registered_on'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Renewal Date</th><td><input type="text" name="domain_renewal_date" class="regular-text" value="<?php echo esc_attr($ov['domain']['renewal_date'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Auto Renew</th><td><input type="text" name="domain_auto_renew" class="regular-text" value="<?php echo esc_attr($ov['domain']['auto_renew'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">DNS Records (freeform)</th><td><textarea name="domain_dns_records" class="large-text" rows="5"><?php echo esc_textarea($ov['domain']['dns_records'] ?? ''); ?></textarea></td></tr>
      </table>

      <?php submit_button('Save Security Data'); ?>
    </form>
  </div>
  <?php
}

/* ============================================================
 * SECURITY FUNCTIONS
 * ============================================================ */
function luna_sanitize_security_overrides($val) {
  $defaults = array(
    'tls' => array('valid' => null, 'version' => '', 'issuer' => '', 'provider_guess' => '', 'valid_from' => '', 'valid_to' => '', 'days_remaining' => '', 'host' => ''),
    'waf' => array('provider' => '', 'last_audit' => '', 'rulesets' => ''),
    'ids' => array('provider' => '', 'last_scan' => '', 'result' => '', 'schedule' => ''),
    'auth' => array('mfa' => '', 'password_policy' => '', 'session_timeout' => '', 'sso_providers' => ''),
    'domain' => array('domain' => '', 'registrar' => '', 'registered_on' => '', 'renewal_date' => '', 'auto_renew' => '', 'dns_records' => ''),
  );
  $val = is_array($val) ? $val : array();
  return array_replace_recursive($defaults, $val);
}

function luna_send_security_to_hub($overrides) {
  $license = get_option(LUNA_WIDGET_OPT_LICENSE, '');
  if (!$license) return false;
  
  $payload = array(
    'security' => $overrides,
  );
  
  // Debug logging
  error_log('[Luna Client] Sending security data to Hub: ' . print_r($payload, true));
  
  $url = luna_widget_hub_url('/wp-json/vl-hub/v1/profile/security?license=' . rawurlencode($license));
  $resp = wp_remote_post($url, array(
    'timeout' => 20,
    'headers' => array(
      'Content-Type' => 'application/json',
      'X-Luna-License' => $license,
      'X-Luna-Site' => home_url('/'),
    ),
    'body' => wp_json_encode($payload),
  ));
  
  if (is_wp_error($resp)) {
    error_log('[Luna Widget] Security sync failed: ' . $resp->get_error_message());
    return false;
  }
  
  $code = wp_remote_retrieve_response_code($resp);
  $body = wp_remote_retrieve_body($resp);
  
  error_log('[Luna Widget] Security sync response: HTTP ' . $code . ' - ' . $body);
  
  if ($code >= 400) {
    error_log('[Luna Widget] Security sync failed: HTTP ' . $code);
    return false;
  }
  
  return true;
}

/* ============================================================
 * HEARTBEAT / HUB HELPERS
 * ============================================================ */
function luna_widget_hub_base() {
  $base = (string) get_option(LUNA_WIDGET_OPT_LICENSE_SERVER, 'https://visiblelight.ai');
  $base = preg_replace('#/+$#','',$base);
  $base = preg_replace('#^http://#i','https://',$base);
  return $base ? $base : 'https://visiblelight.ai';
}
function luna_widget_hub_url($path = '') {
  $path = '/'.ltrim($path,'/');
  return luna_widget_hub_base() . $path;
}
function luna_widget_store_last_ping($url, $resp) {
  $log = array(
    'ts'   => gmdate('c'),
    'url'  => $url,
    'code' => is_wp_error($resp) ? 0 : (int) wp_remote_retrieve_response_code($resp),
    'err'  => is_wp_error($resp) ? $resp->get_error_message() : '',
    'body' => is_wp_error($resp) ? '' : substr((string) wp_remote_retrieve_body($resp), 0, 500),
  );
  update_option(LUNA_WIDGET_OPT_LAST_PING, $log, false);
}
function luna_widget_try_activation() {
  $license = trim((string) get_option(LUNA_WIDGET_OPT_LICENSE, ''));
  if ($license === '') return;
  $body = array(
    'license'        => $license,
    'site_url'       => home_url('/'),
    'site_name'      => get_bloginfo('name'),
    'wp_version'     => get_bloginfo('version'),
    'plugin_version' => LUNA_WIDGET_PLUGIN_VERSION,
  );
  $url = luna_widget_hub_url('/wp-json/vl-license/v1/activate');
  $resp = wp_remote_post($url, array(
    'timeout' => 15,
    'headers' => array(
      'Content-Type'   => 'application/json',
      'X-Luna-License' => $license,
      'X-Luna-Site'    => home_url('/'),
    ),
    'body'    => wp_json_encode($body),
  ));
  luna_widget_store_last_ping($url, $resp);
}
function luna_widget_send_heartbeat() {
  $license = trim((string) get_option(LUNA_WIDGET_OPT_LICENSE, ''));
  if ($license === '') return;
  $body = array(
    'license'        => $license,
    'site_url'       => home_url('/'),
    'wp_version'     => get_bloginfo('version'),
    'plugin_version' => LUNA_WIDGET_PLUGIN_VERSION,
  );
  $url  = luna_widget_hub_url('/wp-json/vl-license/v1/heartbeat');
  $resp = wp_remote_post($url, array(
    'timeout' => 15,
    'headers' => array(
      'Content-Type'   => 'application/json',
      'X-Luna-License' => $license,
      'X-Luna-Site'    => home_url('/'),
    ),
    'body'    => wp_json_encode($body),
  ));
  luna_widget_store_last_ping($url, $resp);
}
add_action('luna_widget_heartbeat_event', function () {
  if (!wp_next_scheduled('luna_widget_heartbeat_event')) {
    wp_schedule_event(time() + 3600, 'hourly', 'luna_widget_heartbeat_event');
  }
  luna_widget_send_heartbeat();
});
add_action('update_option_' . LUNA_WIDGET_OPT_LICENSE, function($old, $new){
  if ($new && $new !== $old) { luna_widget_try_activation(); luna_widget_send_heartbeat(); luna_profile_cache_bust(true); }
}, 10, 2);
add_action('update_option_' . LUNA_WIDGET_OPT_LICENSE_SERVER, function($old, $new){
  if ($new && $new !== $old) { luna_widget_try_activation(); luna_widget_send_heartbeat(); luna_profile_cache_bust(true); }
}, 10, 2);

/* ============================================================
 * CONVERSATIONS: CPT + helpers
 * ============================================================ */
add_action('init', function () {
  register_post_type('luna_widget_convo', array(
    'label'        => 'Luna Conversations',
    'public'       => false,
    'show_ui'      => true,
    'show_in_menu' => false,
    'supports'     => array('title'),
    'map_meta_cap' => true,
  ));
});

function luna_conv_id() {
  $cookie_key = 'luna_widget_cid';
  $cid = isset($_COOKIE[$cookie_key]) ? sanitize_text_field(wp_unslash($_COOKIE[$cookie_key])) : '';
  if (!$cid) {
    $cid = 'lwc_' . wp_generate_uuid4();
    // Use session-based cookie (expires when browser closes)
    @setcookie($cookie_key, $cid, 0, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN ? COOKIE_DOMAIN : '', is_ssl(), true);
    $_COOKIE[$cookie_key] = $cid;
  }
  $existing = get_posts(array(
    'post_type'   => 'luna_widget_convo',
    'meta_key'    => 'luna_cid',
    'meta_value'  => $cid,
    'fields'      => 'ids',
    'numberposts' => 1,
    'post_status' => 'any',
  ));
  if ($existing) return (int)$existing[0];

  $pid = wp_insert_post(array(
    'post_type'   => 'luna_widget_convo',
    'post_title'  => 'Conversation ' . substr($cid, 0, 8),
    'post_status' => 'publish',
  ));
  if ($pid && !is_wp_error($pid)) {
    update_post_meta($pid, 'luna_cid', $cid);
    update_post_meta($pid, 'transcript', array());
    return (int)$pid;
  }
  return 0;
}
function luna_log_turn($user, $assistant, $meta = array()) {
  $pid = luna_conv_id(); if (!$pid) return;
  $t = get_post_meta($pid, 'transcript', true);
  if (!is_array($t)) $t = array();
  $t[] = array('ts'=>time(), 'user'=>$user, 'assistant'=>$assistant, 'meta'=>$meta);
  update_post_meta($pid, 'transcript', $t);
  
  // Also log to Hub
  luna_log_conversation_to_hub($t);
}

/* Log conversation to Hub */
function luna_log_conversation_to_hub($transcript) {
  $license = luna_get_license();
  if (!$license) {
    error_log('Luna Hub Log: No license found');
    return false;
  }
  
  $hub_url = luna_widget_hub_base();
  $conversation_data = array(
    'id' => 'conv_' . uniqid('', true),
    'started_at' => !empty($transcript[0]['ts']) ? gmdate('c', (int)$transcript[0]['ts']) : gmdate('c'),
    'transcript' => $transcript
  );
  
  error_log('Luna Hub Log: Sending conversation to Hub: ' . print_r($conversation_data, true));
  
  $response = wp_remote_post($hub_url . '/wp-json/luna_widget/v1/conversations/log', array(
    'headers' => array(
      'X-Luna-License' => $license,
      'Content-Type' => 'application/json'
    ),
    'body' => wp_json_encode($conversation_data),
    'timeout' => 10
  ));
  
  if (is_wp_error($response)) {
    error_log('Luna Hub Log: Error sending to Hub: ' . $response->get_error_message());
    return false;
  }
  
  $response_code = wp_remote_retrieve_response_code($response);
  $response_body = wp_remote_retrieve_body($response);
  
  error_log('Luna Hub Log: Hub response code: ' . $response_code);
  error_log('Luna Hub Log: Hub response body: ' . $response_body);
  
  return $response_code >= 200 && $response_code < 300;
}

/* ============================================================
 * HUB PROFILE FETCH (LICENSE-GATED) + FACTS
 * ============================================================ */
function luna_get_license() { return trim((string) get_option(LUNA_WIDGET_OPT_LICENSE, '')); }

function luna_profile_cache_key() {
  $license = luna_get_license();
  $hub     = luna_widget_hub_base();
  $site    = home_url('/');
  return 'luna_profile_' . md5($license . '|' . $hub . '|' . $site);
}
function luna_profile_cache_bust($all=false){
  // Single-site cache key; $all kept for API symmetry
  delete_transient( luna_profile_cache_key() );
}

function luna_hub_get_json($path) {
  $license = luna_get_license();
  if ($license === '') return null;
  
  // Add license parameter to URL if not already present
  $url = luna_widget_hub_url($path);
  if (strpos($url, '?') !== false) {
    $url .= '&license=' . rawurlencode($license);
  } else {
    $url .= '?license=' . rawurlencode($license);
  }
  
  $resp = wp_remote_get($url, array(
    'timeout' => 12,
    'headers' => array(
      'X-Luna-License' => $license,
      'X-Luna-Site'    => home_url('/'),
      'Accept'         => 'application/json'
    ),
    'sslverify' => true,
  ));
  if (is_wp_error($resp)) return null;
  $code = (int) wp_remote_retrieve_response_code($resp);
  if ($code >= 400) return null;
  $body = json_decode(wp_remote_retrieve_body($resp), true);
  return is_array($body) ? $body : null;
}

function luna_hub_profile() {
  if (isset($_GET['luna_profile_nocache'])) luna_profile_cache_bust();
  $key = luna_profile_cache_key();
  $cached = get_transient($key);
  if (is_array($cached)) return $cached;

  $map = isset($GLOBALS['LUNA_HUB_ENDPOINTS']) ? $GLOBALS['LUNA_HUB_ENDPOINTS'] : array();
  $profile = luna_hub_get_json(isset($map['profile']) ? $map['profile'] : '/wp-json/vl-hub/v1/profile');

  if (!$profile) {
    // Fallback to local data only if Hub profile is not available
    $profile = array(
      'site'      => array('url' => home_url('/')),
      'wordpress' => array('version' => get_bloginfo('version')),
      'security'  => array(),
      'content'   => array(),
      'users'     => array(),
    );
  }

  set_transient($key, $profile, LUNA_CACHE_PROFILE_TTL);
  return $profile;
}

/* Build compact facts, prioritizing Hub over local snapshot; no network/probe overrides */
function luna_profile_facts() {
  $hub   = luna_hub_profile();
  $local = luna_snapshot_system(); // fallback only

  $site_url = isset($hub['site']['url']) ? (string)$hub['site']['url'] : home_url('/');

  // TLS from Hub (authoritative)
  $tls        = isset($hub['security']['tls']) ? $hub['security']['tls'] : array();
  $tls_valid  = (bool) ( isset($tls['valid']) ? $tls['valid'] : ( isset($hub['security']['tls_valid']) ? $hub['security']['tls_valid'] : false ) );
  $tls_issuer = isset($tls['issuer']) ? (string)$tls['issuer'] : '';
  $tls_expires= isset($tls['expires_at']) ? (string)$tls['expires_at'] : ( isset($tls['not_after']) ? (string)$tls['not_after'] : '' );
  $tls_checked= isset($tls['checked_at']) ? (string)$tls['checked_at'] : '';

  // Host/Infra from Hub
  $host  = '';
  if (isset($hub['infra']['host'])) $host = (string)$hub['infra']['host'];
  elseif (isset($hub['hosting']['provider'])) $host = (string)$hub['hosting']['provider'];

  // WordPress version from Hub then local
  $wpv   = isset($hub['wordpress']['version']) ? (string)$hub['wordpress']['version'] : ( isset($local['wordpress']['version']) ? (string)$local['wordpress']['version'] : '' );
  // Theme: prefer Hub if provided as object with name; else local
  $theme = (isset($hub['wordpress']['theme']) && is_array($hub['wordpress']['theme']) && isset($hub['wordpress']['theme']['name']))
    ? (string)$hub['wordpress']['theme']['name']
    : ( isset($local['wordpress']['theme']['name']) ? (string)$local['wordpress']['theme']['name'] : '' );

  // Content counts (Hub first)
  $pages = 0; $posts = 0;
  if (isset($hub['content']['pages_total'])) $pages = (int)$hub['content']['pages_total'];
  elseif (isset($hub['content']['pages']))   $pages = (int)$hub['content']['pages'];
  if (isset($hub['content']['posts_total'])) $posts = (int)$hub['content']['posts_total'];
  elseif (isset($hub['content']['posts']))   $posts = (int)$hub['content']['posts'];

  // Users
  $users_total = isset($hub['users']['total']) ? (int)$hub['users']['total'] : 0;

  // Updates (Hub first; fallback to local counts)
  $plugin_updates = isset($hub['updates']['plugins_pending']) ? (int)$hub['updates']['plugins_pending'] : 0;
  $theme_updates  = isset($hub['updates']['themes_pending'])  ? (int)$hub['updates']['themes_pending']  : 0;
  if ($plugin_updates === 0 || $theme_updates === 0) {
    $pl = isset($local['plugins']) ? $local['plugins'] : array();
    $th = isset($local['themes'])  ? $local['themes']  : array();
    if ($plugin_updates === 0) {
      $c = 0; foreach ($pl as $p) { if (!empty($p['update_available'])) $c++; } $plugin_updates = $c;
    }
    if ($theme_updates === 0) {
      $c = 0; foreach ($th as $t) { if (!empty($t['update_available'])) $c++; } $theme_updates = $c;
    }
  }

  return array(
    'site_url'   => $site_url,
    'tls'        => array(
      'valid'    => (bool)$tls_valid,
      'issuer'   => $tls_issuer,
      'expires'  => $tls_expires,
      'checked'  => $tls_checked,
    ),
    'host'       => $host,
    'wp_version' => $wpv,
    'theme'      => $theme,
    'counts'     => array('pages'=>$pages, 'posts'=>$posts, 'users'=>$users_total),
    'updates'    => array('plugins'=>$plugin_updates, 'themes'=>$theme_updates),
    'generated'  => gmdate('c'),
  );
}

/* Enhanced facts with comprehensive Hub data */
function luna_get_active_theme_status($comprehensive) {
  // First try to get from themes array (more accurate)
  if (isset($comprehensive['themes']) && is_array($comprehensive['themes'])) {
    foreach ($comprehensive['themes'] as $theme) {
      if (isset($theme['is_active']) && $theme['is_active']) {
        return true;
      }
    }
  }
  
  // Fallback to basic theme info
  return isset($comprehensive['wordpress']['theme']['is_active']) ? (bool)$comprehensive['wordpress']['theme']['is_active'] : true;
}

function luna_profile_facts_comprehensive() {
  $license = luna_get_license();
  if (!$license) {
    error_log('[Luna] No license key found, falling back to basic facts');
    return luna_profile_facts(); // fallback to basic facts
  }
  
  // Try to fetch comprehensive data from Hub
  $hub_url = luna_widget_hub_base();
  $endpoint = $hub_url . '/wp-json/luna_widget/v1/system/comprehensive';
  
  error_log('[Luna] Fetching comprehensive data from: ' . $endpoint);
  error_log('[Luna] Using license: ' . substr($license, 0, 8) . '...');
  
  $response = wp_remote_get($endpoint, array(
    'headers' => array('X-Luna-License' => $license),
    'timeout' => 10
  ));
  
  if (is_wp_error($response)) {
    error_log('[Luna] Error fetching comprehensive data: ' . $response->get_error_message());
    return luna_profile_facts(); // fallback
  }
  
  $code = wp_remote_retrieve_response_code($response);
  error_log('[Luna] Response code: ' . $code);
  
  if ($code < 200 || $code >= 300) {
    error_log('[Luna] HTTP error, falling back to basic facts');
    return luna_profile_facts(); // fallback
  }
  
  $comprehensive = json_decode(wp_remote_retrieve_body($response), true);
  if (!is_array($comprehensive)) {
    error_log('[Luna] Invalid JSON response, falling back to basic facts');
    return luna_profile_facts(); // fallback
  }
  
  error_log('[Luna] Successfully fetched comprehensive data: ' . print_r($comprehensive, true));
  
  // Build enhanced facts from comprehensive data
  $site_url = isset($comprehensive['home_url']) ? (string)$comprehensive['home_url'] : home_url('/');
  
  // Add comprehensive data to facts for AI context
  $facts = array(
    'site_url'   => $site_url,
    'https'      => isset($comprehensive['https']) ? (bool)$comprehensive['https'] : is_ssl(),
    'tls'        => array(
      'valid'    => isset($comprehensive['security']['tls']['valid']) ? (bool)$comprehensive['security']['tls']['valid'] : false,
      'issuer'   => isset($comprehensive['security']['tls']['issuer']) ? (string)$comprehensive['security']['tls']['issuer'] : '',
      'expires'  => isset($comprehensive['security']['tls']['expires']) ? (string)$comprehensive['security']['tls']['expires'] : '',
    ),
    'host'       => isset($comprehensive['host']) ? (string)$comprehensive['host'] : '',
    'wp_version' => isset($comprehensive['wordpress']['version']) ? (string)$comprehensive['wordpress']['version'] : get_bloginfo('version'),
    'theme'      => isset($comprehensive['wordpress']['theme']['name']) ? (string)$comprehensive['wordpress']['theme']['name'] : '',
    'theme_version' => isset($comprehensive['wordpress']['theme']['version']) ? (string)$comprehensive['wordpress']['theme']['version'] : '',
    'theme_active' => luna_get_active_theme_status($comprehensive),
    'counts'     => array(
      'pages' => isset($comprehensive['_pages']['items']) && is_array($comprehensive['_pages']['items']) ? count($comprehensive['_pages']['items']) : 0,
      'posts' => isset($comprehensive['_posts']['items']) && is_array($comprehensive['_posts']['items']) ? count($comprehensive['_posts']['items']) : 0,
      'users' => isset($comprehensive['users']) && is_array($comprehensive['users']) ? count($comprehensive['users']) : 0,
      'plugins' => isset($comprehensive['plugins']) && is_array($comprehensive['plugins']) ? count($comprehensive['plugins']) : 0,
    ),
    'updates'    => array(
      'plugins' => 0, // Would need to calculate from plugins data
      'themes' => 0, // Calculate from themes data
      'core' => isset($comprehensive['wordpress']['core_update_available']) ? ($comprehensive['wordpress']['core_update_available'] ? 1 : 0) : 0
    ),
    'generated'  => gmdate('c'),
    'comprehensive' => true, // Flag to indicate this is comprehensive data
    'plugins' => isset($comprehensive['plugins']) ? $comprehensive['plugins'] : array(),
    'users' => isset($comprehensive['users']) ? $comprehensive['users'] : array(),
    'themes' => isset($comprehensive['themes']) ? $comprehensive['themes'] : array(),
    'posts' => isset($comprehensive['_posts']['items']) ? $comprehensive['_posts']['items'] : array(),
    'pages' => isset($comprehensive['_pages']['items']) ? $comprehensive['_pages']['items'] : array(),
    'security' => isset($comprehensive['security']) ? $comprehensive['security'] : array(),  );
  
  // Calculate theme updates
  if (isset($facts['themes']) && is_array($facts['themes'])) {
    $theme_updates = 0;
    foreach ($facts['themes'] as $theme) {
      if (!empty($theme['update_available'])) {
        $theme_updates++;
      }
    }
    $facts['updates']['themes'] = $theme_updates;
  }
  
  // Calculate plugin updates
  if (isset($facts['plugins']) && is_array($facts['plugins'])) {
    $plugin_updates = 0;
    foreach ($facts['plugins'] as $plugin) {
      if (!empty($plugin['update_available'])) {
        $plugin_updates++;
      }
    }
    $facts['updates']['plugins'] = $plugin_updates;
  }
  
  error_log('[Luna] Built comprehensive facts: ' . print_r($facts, true));
  
  return $facts;
}

/* Local snapshot used ONLY as fallback when Hub fact missing */
function luna_snapshot_system() {
  global $wp_version; $theme = wp_get_theme();
  if (!function_exists('get_plugins')) { @require_once ABSPATH . 'wp-admin/includes/plugin.php'; }
  $plugins = function_exists('get_plugins') ? (array)get_plugins() : array();
  $active  = (array) get_option('active_plugins', array());
  $up_pl   = get_site_transient('update_plugins');

  $plugins_out = array();
  foreach ($plugins as $slug => $info) {
    $update_available = isset($up_pl->response[$slug]);
    $plugins_out[] = array(
      'slug' => $slug,
      'name' => isset($info['Name']) ? $info['Name'] : $slug,
      'version' => isset($info['Version']) ? $info['Version'] : null,
      'active' => in_array($slug, $active, true),
      'update_available' => (bool)$update_available,
      'new_version' => $update_available ? (isset($up_pl->response[$slug]->new_version) ? $up_pl->response[$slug]->new_version : null) : null,
    );
  }
  $themes = wp_get_themes(); $up_th = get_site_transient('update_themes');
  $themes_out = array();
  foreach ($themes as $stylesheet => $th) {
    $update_available = isset($up_th->response[$stylesheet]);
    $themes_out[] = array(
      'stylesheet' => $stylesheet,
      'name' => $th->get('Name'),
      'version' => $th->get('Version'),
      'is_active' => (wp_get_theme()->get_stylesheet() === $stylesheet),
      'update_available' => (bool)$update_available,
      'new_version' => $update_available ? (isset($up_th->response[$stylesheet]['new_version']) ? $up_th->response[$stylesheet]['new_version'] : null) : null,
    );
  }

  // Check for WordPress core updates
  $core_updates = get_site_transient('update_core');
  $core_update_available = false;
  if (isset($core_updates->updates) && is_array($core_updates->updates)) {
    foreach ($core_updates->updates as $update) {
      if ($update->response === 'upgrade') {
        $core_update_available = true;
        break;
      }
    }
  }

  return array(
    'site' => array('home_url' => home_url('/'), 'https' => (wp_parse_url(home_url('/'), PHP_URL_SCHEME) === 'https')),
    'wordpress' => array(
      'version' => isset($wp_version) ? $wp_version : null,
      'core_update_available' => $core_update_available,
      'theme'   => array(
        'name'       => $theme->get('Name'),
        'version'    => $theme->get('Version'),
        'stylesheet' => $theme->get_stylesheet(),
        'template'   => $theme->get_template(),
      ),
    ),
    'plugins'     => $plugins_out,
    'themes'      => $themes_out,
    'generated_at'=> gmdate('c'),
  );
}

/* ============================================================
 * FRONT-END: Widget/Shortcode + JS (with history hydrate)
 * ============================================================ */
add_shortcode('luna_chat', function(){
  if (get_option(LUNA_WIDGET_OPT_MODE, 'widget') !== 'shortcode') {
    return '<!-- [luna_chat] disabled: floating widget active -->';
  }
  ob_start(); ?>
  <div class="luna-wrap">
    <div class="luna-thread"></div>
    <form class="luna-form" onsubmit="return false;">
      <input class="luna-input" autocomplete="off" placeholder="Ask Luna…" />
      <button class="luna-send" type="submit">Send</button>
    </form>
  </div>
  <?php return ob_get_clean();
});

add_action('wp_footer', function () {
  if (is_admin()) return;

  $mode = get_option(LUNA_WIDGET_OPT_MODE, 'widget');
  $ui   = get_option(LUNA_WIDGET_OPT_SETTINGS, array());
  $pos  = isset($ui['position']) ? $ui['position'] : 'bottom-right';

  if ($mode === 'widget') {
    $pos_css = 'bottom:20px;right:20px;';
    if ($pos === 'top-left') { $pos_css = 'top:20px;left:20px;'; }
    elseif ($pos === 'top-center') { $pos_css = 'top:20px;left:50%;transform:translateX(-50%);'; }
    elseif ($pos === 'top-right') { $pos_css = 'top:20px;right:20px;'; }
    elseif ($pos === 'bottom-left') { $pos_css = 'bottom:20px;left:20px;'; }
    elseif ($pos === 'bottom-center') { $pos_css = 'bottom:20px;left:50%;transform:translateX(-50%);'; }

    $title = esc_html(isset($ui['title']) ? $ui['title'] : 'Luna Chat');
    $avatar= esc_url(isset($ui['avatar_url']) ? $ui['avatar_url'] : '');
    $hdr   = esc_html(isset($ui['header_text']) ? $ui['header_text'] : "Hi, I'm Luna");
    $sub   = esc_html(isset($ui['sub_text']) ? $ui['sub_text'] : 'How can I help today?');

    $panel_anchor = (strpos($pos,'bottom') !== false ? 'bottom:80px;' : 'top:80px;')
                  . (strpos($pos,'right') !== false ? 'right:20px;' : (strpos($pos,'left') !== false ? 'left:20px;' : 'left:50%;transform:translateX(-50%);'));
    ?>
    <style>
      .luna-fab { position:fixed; z-index:99990; <?php echo $pos_css; ?> }
      .luna-launcher{display:flex;align-items:center;gap:10px;background:#111;color:#fff;border:1px solid #5A5753;border-radius:999px;padding:8px 12px 8px 8px;cursor:pointer;box-shadow:0 8px 24px rgba(0,0,0,.25)}
      .luna-launcher .ava{width:36px;height:36px;border-radius:50%;background:#222;overflow:hidden;display:inline-flex;align-items:center;justify-content:center}
      .luna-launcher .txt{line-height:1.2;display:flex;flex-direction:column}
      .luna-panel{position:fixed; z-index:99991; <?php echo $panel_anchor; ?> width:clamp(320px,92vw,420px);max-height:min(70vh,560px);display:none;flex-direction:column;border-radius:12px;border:1px solid #5A5753;background:#000;color:#fff;overflow:hidden;box-shadow:0 24px 48px rgba(0,0,0,.4)}
      .luna-panel.show{display:flex}
      .luna-head{padding:10px 12px;font-weight:600;background:#0b0b0b;border-bottom:1px solid #333;display:flex;align-items:center;justify-content:space-between}
      .luna-thread{padding:10px 12px;overflow:auto;flex:1 1 auto}
      .luna-form{display:flex;gap:8px;padding:10px 12px;border-top:1px solid #333}
      .luna-input{flex:1 1 auto;background:#111;color:#fff;border:1px solid #333;border-radius:10px;padding:8px 10px}
      .luna-send{background:#111;color:#fff;border:1px solid #5A5753;border-radius:10px;padding:8px 12px;cursor:pointer}
      .luna-thread .luna-msg{clear:both;margin:6px 0}
      .luna-thread .luna-user{float:right;background:#fff4e9;color:#000;display:inline-block;padding:8px 10px;border-radius:10px;max-width:85%;word-wrap:break-word}
      .luna-thread .luna-assistant{float:left;background:#111;border:1px solid #333;color:#fff;display:inline-block;padding:8px 10px;border-radius:10px;max-width:85%;word-wrap:break-word}
    </style>
    <div class="luna-fab" aria-live="polite">
      <button class="luna-launcher" aria-expanded="false" aria-controls="luna-panel" title="<?php echo $title; ?>">
        <span class="ava">
          <?php if ($avatar): ?><img src="<?php echo $avatar; ?>" alt="" style="width:36px;height:36px;object-fit:cover"><?php else: ?>
            <svg width="24" height="24" viewBox="0 0 36 36" fill="none" aria-hidden="true"><circle cx="18" cy="18" r="18" fill="#222"/><path d="M18 18a6 6 0 100-12 6 6 0 000 12zm0 2c-6 0-10 3.2-10 6v2h20v-2c0-2.8-4-6-10-6z" fill="#666"/></svg>
          <?php endif; ?>
        </span>
        <span class="txt"><strong><?php echo $hdr; ?></strong><span><?php echo $sub; ?></span></span>
      </button>
      <div id="luna-panel" class="luna-panel" role="dialog" aria-label="<?php echo $title; ?>">
        <div class="luna-head"><span><?php echo $title; ?></span><button class="luna-close" style="background:transparent;border:0;color:#fff;cursor:pointer" aria-label="Close">✕</button></div>
        <div class="luna-thread"></div>
        <form class="luna-form"><input class="luna-input" placeholder="Ask Luna…" autocomplete="off"><button type="button" class="luna-send">Send</button></form>
      </div>
    </div>
    <script>
      (function(){
        var fab=document.querySelector('.luna-launcher'), panel=document.querySelector('#luna-panel');
        var closeBtn=document.querySelector('.luna-close');

        async function hydrate(thread){
          if (!thread || thread.__hydrated) return;
          try{
            const res = await fetch('<?php echo esc_url_raw( rest_url('luna_widget/v1/chat/history') ); ?>');
            const data = await res.json();
            if (data && Array.isArray(data.items)) {
              data.items.forEach(function(turn){
                if (turn.user) { var u=document.createElement('div'); u.className='luna-msg luna-user'; u.textContent=turn.user; thread.appendChild(u); }
                if (turn.assistant) { var a=document.createElement('div'); a.className='luna-msg luna-assistant'; a.textContent=turn.assistant; thread.appendChild(a); }
              });
              thread.scrollTop = thread.scrollHeight;
            }
          }catch(e){ console.warn('[Luna] hydrate failed', e); }
          finally { thread.__hydrated = true; }
        }
        function toggle(open){
          if(!panel||!fab) return;
          var will=(typeof open==='boolean')?open:!panel.classList.contains('show');
          panel.classList.toggle('show',will);
          fab.setAttribute('aria-expanded',will?'true':'false');
          if (will) hydrate(panel.querySelector('.luna-thread'));
        }
        if(fab) fab.addEventListener('click', function(){ toggle(); });
        if(closeBtn) closeBtn.addEventListener('click', function(){ toggle(false); });
        document.addEventListener('keydown', function(e){ if(e.key==='Escape') toggle(false); });
      })();
    </script>
    <?php
  }
  ?>
  <script>
    (function(){
      if (window.__lunaBoot) return; window.__lunaBoot = true;

      async function hydrateAny(){
        document.querySelectorAll('.luna-thread').forEach(async function(thread){
          if (thread.closest('#luna-panel')) return;
          if (!thread.__hydrated) {
            try{
              const r = await fetch('<?php echo esc_url_raw( rest_url('luna_widget/v1/chat/history') ); ?>');
              const d = await r.json();
              if (d && Array.isArray(d.items)) {
                d.items.forEach(function(turn){
                  if (turn.user) { var u=document.createElement('div'); u.className='luna-msg luna-user'; u.textContent=turn.user; thread.appendChild(u); }
                  if (turn.assistant) { var a=document.createElement('div'); a.className='luna-msg luna-assistant'; a.textContent=turn.assistant; thread.appendChild(a); }
                });
                thread.scrollTop = thread.scrollHeight;
              }
            }catch(e){ console.warn('[Luna] hydrate failed', e); }
            finally { thread.__hydrated = true; }
          }
        });
      }

      function submitFrom(form){
        try{
          var input = form.querySelector('.luna-input'); if(!input) return;
          var text = (input.value||'').trim(); if(!text) return;

          var thread = form.parentElement.querySelector('.luna-thread') || document.querySelector('.luna-thread');
          if (!thread) { thread = document.createElement('div'); thread.className='luna-thread'; form.parentElement.insertBefore(thread, form); }

          var btn = form.querySelector('.luna-send, button[type="submit"]');
          input.disabled=true; if(btn) btn.disabled=true;

          var u=document.createElement('div'); u.className='luna-msg luna-user'; u.textContent=text; thread.appendChild(u); thread.scrollTop=thread.scrollHeight;

          fetch('<?php echo esc_url_raw( rest_url('luna_widget/v1/chat') ); ?>', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ prompt: text })
          })
          .then(function(r){ return r.json().catch(function(){return {};}); })
          .then(function(d){
            var msg = (d && d.answer) ? d.answer : (d.error ? ('Error: '+d.error) : 'Sorry—no response.');
            var a=document.createElement('div'); a.className='luna-msg luna-assistant'; a.textContent=msg; thread.appendChild(a); thread.scrollTop=thread.scrollHeight;
          })
          .catch(function(err){
            var e=document.createElement('div'); e.className='luna-msg luna-assistant'; e.textContent='Network error. Please try again.'; thread.appendChild(e);
            console.error('[Luna]', err);
          })
          .finally(function(){ input.value=''; input.disabled=false; if(btn) btn.disabled=false; input.focus(); });
        }catch(e){ console.error('[Luna unexpected]', e); }
      }

      function bind(form){
        if(!form || form.__bound) return; form.__bound = true;
        form.setAttribute('novalidate','novalidate');
        form.addEventListener('submit', function(e){ e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation(); submitFrom(form); }, true);
        var input=form.querySelector('.luna-input'), btn=form.querySelector('.luna-send');
        if (input) input.addEventListener('keydown', function(e){ if(e.key==='Enter' && !e.shiftKey && !e.isComposing){ e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation(); submitFrom(form);} }, true);
        if (btn) { try{btn.type='button';}catch(_){} btn.addEventListener('click', function(e){ e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation(); submitFrom(form); }, true); }
      }

      function scan(){ document.querySelectorAll('.luna-form').forEach(bind); }
      scan(); hydrateAny();
      try{ new MutationObserver(function(){ if (scan.__t) cancelAnimationFrame(scan.__t); scan.__t=requestAnimationFrame(function(){ scan(); hydrateAny(); }); }).observe(document.documentElement,{childList:true,subtree:true}); }catch(_){}
      if (document.readyState==='loading') document.addEventListener('DOMContentLoaded', function(){ scan(); hydrateAny(); }, {once:true});
    })();
  </script>
  <?php
});

/* ============================================================
 * OPENAI HELPERS
 * ============================================================ */
function luna_get_openai_key() {
  if (defined('LUNA_OPENAI_API_KEY') && LUNA_OPENAI_API_KEY) return (string)LUNA_OPENAI_API_KEY;
  $k = get_option('luna_openai_api_key', '');
  return is_string($k) ? trim($k) : '';
}

function luna_openai_messages_with_facts($pid, $user_text, $facts) {
  $facts_text = "FACTS (from Visible Light Hub)\n"
    . "- Site URL: " . $facts['site_url'] . "\n"
    . "- HTTPS: " . (isset($facts['https']) ? ($facts['https'] ? 'yes' : 'no') : 'unknown') . "\n"
    . "- TLS valid: " . (isset($facts['tls']['valid']) ? ($facts['tls']['valid'] ? 'yes' : 'no') : 'unknown')
    . (!empty($facts['tls']['issuer']) ? " (issuer: " . $facts['tls']['issuer'] . ")" : '')
    . (!empty($facts['tls']['expires']) ? " (expires: " . $facts['tls']['expires'] . ")" : '') . "\n"
    . "- Host: " . ($facts['host'] ? $facts['host'] : 'unknown') . "\n"
    . "- WordPress: " . ($facts['wp_version'] ? $facts['wp_version'] : 'unknown') . "\n"
    . "- Theme: " . ($facts['theme'] ? $facts['theme'] : 'unknown') . " (version: " . (isset($facts['theme_version']) ? $facts['theme_version'] : 'unknown') . ")\n"
    . "- Theme active: " . (isset($facts['theme_active']) ? ($facts['theme_active'] ? 'yes' : 'no') : 'yes') . "\n"
    . "- Counts: pages " . $facts['counts']['pages'] . ", posts " . $facts['counts']['posts'] . ", users " . $facts['counts']['users'] . ", plugins " . (isset($facts['counts']['plugins']) ? $facts['counts']['plugins'] : 'unknown') . "\n"
    . "- Updates pending: plugins " . $facts['updates']['plugins'] . ", themes " . $facts['updates']['themes'] . ", WordPress Core " . $facts['updates']['core'] . "\n";
    
  // Add comprehensive data if available
  if (isset($facts['comprehensive']) && $facts['comprehensive']) {
    $facts_text .= "\nINSTALLED PLUGINS:\n";
    if (isset($facts['plugins']) && is_array($facts['plugins'])) {
      foreach ($facts['plugins'] as $plugin) {
        $status = !empty($plugin['active']) ? 'active' : 'inactive';
        $update = !empty($plugin['update_available']) ? ' (update available)' : '';
        $facts_text .= "- " . $plugin['name'] . " v" . $plugin['version'] . " (" . $status . ")" . $update . "\n";
      }
    }
    
    $facts_text .= "\nINSTALLED THEMES:\n";
    if (isset($facts['themes']) && is_array($facts['themes'])) {
      foreach ($facts['themes'] as $theme) {
        $status = !empty($theme['is_active']) ? 'active' : 'inactive';
        $update = !empty($theme['update_available']) ? ' (update available)' : '';
        $facts_text .= "- " . $theme['name'] . " v" . $theme['version'] . " (" . $status . ")" . $update . "\n";
      }
    }
    
    $facts_text .= "\nPUBLISHED POSTS:\n";
    if (isset($facts['posts']) && is_array($facts['posts'])) {
      foreach ($facts['posts'] as $post) {
        $facts_text .= "- " . $post['title'] . " (ID: " . $post['id'] . ")\n";
      }
    }
    
    $facts_text .= "\nPAGES:\n";
    if (isset($facts['pages']) && is_array($facts['pages'])) {
      foreach ($facts['pages'] as $page) {
        $status = isset($page['status']) ? $page['status'] : 'published';
        $facts_text .= "- " . $page['title'] . " (" . $status . ", ID: " . $page['id'] . ")\n";
      }
    }
    
    $facts_text .= "\nUSERS:\n";
    if (isset($facts['users']) && is_array($facts['users'])) {
      foreach ($facts['users'] as $user) {
        $facts_text .= "- " . $user['name'] . " (" . $user['username'] . ") - " . $user['email'] . "\n";
      }
    }
  }
  
  $facts_text .= "\nRULES: Prefer the FACTS for this client. If a fact is missing/uncertain, say you're unsure and suggest next steps. Keep answers concise and specific to this site when relevant.";

  $messages = array(
    array('role'=>'system','content'=>"You are Luna, a concise, friendly assistant for the site’s owners."),
    array('role'=>'system','content'=>$facts_text),
  );
  $t = get_post_meta($pid, 'transcript', true);
  if (!is_array($t)) $t = array();
  $slice = array_slice($t, max(0, count($t)-8));
  foreach ($slice as $row) {
    $u = trim(isset($row['user']) ? (string)$row['user'] : '');
    $a = trim(isset($row['assistant']) ? (string)$row['assistant'] : '');
    if ($u !== '') $messages[] = array('role'=>'user','content'=>$u);
    if ($a !== '') $messages[] = array('role'=>'assistant','content'=>$a);
  }
  if ($user_text !== '') $messages[] = array('role'=>'user','content'=>$user_text);
  return $messages;
}

/* ============================================================
 * REST: Chat + History + Hub-facing lists + Utilities
 * ============================================================ */
add_action('rest_api_init', function () {

  /* --- CHAT --- */
  register_rest_route('luna_widget/v1', '/chat', array(
    'methods'  => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function( WP_REST_Request $req ){
      $prompt = trim( (string) $req->get_param('prompt') );
      if ($prompt === '') return new WP_REST_Response(array('answer'=>'Please enter a message.'), 200);

      $pid   = luna_conv_id();
      $facts = luna_profile_facts_comprehensive(); // Use comprehensive data
      $lc    = function_exists('mb_strtolower') ? mb_strtolower($prompt) : strtolower($prompt);
      $answer = '';
      
      // Debug: Log the facts being used
      error_log('[Luna Chat] Using facts: ' . print_r($facts, true));
      error_log('[Luna Chat] User prompt: ' . $prompt);
      error_log('[Luna Chat] Lowercase prompt: ' . $lc);
      
      // Check for keyword mappings first
      $keyword_match = luna_check_keyword_mappings($prompt);
      if ($keyword_match) {
        error_log('[Luna Chat] Keyword match found: ' . print_r($keyword_match, true));
        $answer = luna_handle_keyword_response($keyword_match, $facts);
        if ($answer) {
          // Track successful keyword usage
          luna_track_keyword_usage($keyword_match, true);
          error_log('[Luna Chat] Returning keyword response: ' . $answer);
          return new WP_REST_Response(['ok' => true, 'answer' => $answer], 200);
        } else {
          // Track failed keyword usage
          luna_track_keyword_usage($keyword_match, false);
          error_log('[Luna Chat] Keyword match failed to generate response');
        }
      } else {
        error_log('[Luna Chat] No keyword match found, proceeding to regex patterns');
      }

      // Deterministic intents that must use Hub facts
      if (preg_match('/\b(tls|ssl|https|certificate|cert)\b/', $lc)) {
        if (!empty($facts['tls'])) {
          if (!empty($facts['tls']['valid'])) {
            $extras = array();
            if (!empty($facts['tls']['issuer']))  $extras[] = "issuer: ".$facts['tls']['issuer'];
            if (!empty($facts['tls']['expires'])) $extras[] = "expires: ".$facts['tls']['expires'];
            $answer = "Yes—TLS/SSL is active for ".$facts['site_url'].( $extras ? " (".implode(', ',$extras).")." : "." );
          } else {
            $answer = "Hub shows TLS/SSL is not confirmed active for ".$facts['site_url'].". Please review the Security tab in Visible Light. If you’d like, we can provision or renew a certificate.";
          }
        } else {
          $answer = "I don’t see TLS/SSL details in the Hub profile. Please confirm in the Security tab.";
        }
      }
      elseif (preg_match('/\bhow many (users|user)\b|\busers?\s*(count|total)?\b/', $lc)) {
        $u = (int)$facts['counts']['users'];
        $answer = ($u > 0) ? ("You have ".$u." registered user".($u===1?'':'s').".") : "I don’t see a confirmed users total in the Hub profile.";
      }
      elseif (preg_match('/\bhow many pages\b|\bpages?\s*(count|total)?\b/', $lc)) {
        $p = (int)$facts['counts']['pages'];
        $answer = "There ".($p===1?'is':'are')." ".$p." page".($p===1?'':'s').".";
      }
      elseif (preg_match('/\bnames.*of.*pages|page.*names|what.*are.*the.*names.*of.*pages\b/', $lc)) {
        error_log('[Luna Chat] Matched page names pattern');
        if (isset($facts['pages']) && is_array($facts['pages']) && !empty($facts['pages'])) {
          error_log('[Luna Chat] Found pages in facts: ' . print_r($facts['pages'], true));
          $page_names = array();
          foreach ($facts['pages'] as $page) {
            $status = isset($page['status']) ? $page['status'] : 'published';
            $page_names[] = $page['title'] . " (" . $status . ")";
          }
          $answer = "The pages are: " . implode(", ", $page_names) . ".";
        } else {
          error_log('[Luna Chat] No pages found in facts');
          $answer = "I don't see any pages in the Hub profile.";
        }
      }
      elseif (preg_match('/\binactive.*page|page.*inactive|draft.*page|page.*draft\b/', $lc)) {
        error_log('[Luna Chat] Matched inactive pages pattern');
        if (isset($facts['pages']) && is_array($facts['pages']) && !empty($facts['pages'])) {
          $inactive_pages = array();
          foreach ($facts['pages'] as $page) {
            $status = isset($page['status']) ? $page['status'] : 'published';
            if ($status !== 'publish') {
              $inactive_pages[] = $page['title'] . " (" . $status . ")";
            }
          }
          if (!empty($inactive_pages)) {
            $answer = "Yes, you have " . count($inactive_pages) . " inactive page(s): " . implode(", ", $inactive_pages) . ".";
          } else {
            $answer = "No, all your pages are published.";
          }
        } else {
          $answer = "I don't see any pages in the Hub profile.";
        }
      }
      elseif (preg_match('/\bhow many posts\b|\bposts?\s*(count|total)?\b/', $lc)) {
        $p = (int)$facts['counts']['posts'];
        $answer = "There ".($p===1?'is':'are')." ".$p." published post".($p===1?'':'s').".";
      }
      elseif (preg_match('/\bnames.*of.*posts|post.*names|what.*are.*the.*names.*of.*posts\b/', $lc)) {
        error_log('[Luna Chat] Matched post names pattern');
        if (isset($facts['posts']) && is_array($facts['posts']) && !empty($facts['posts'])) {
          error_log('[Luna Chat] Found posts in facts: ' . print_r($facts['posts'], true));
          $post_names = array();
          foreach ($facts['posts'] as $post) {
            $status = isset($post['status']) ? $post['status'] : 'published';
            $post_names[] = $post['title'] . " (" . $status . ")";
          }
          $answer = "The posts are: " . implode(", ", $post_names) . ".";
        } else {
          error_log('[Luna Chat] No posts found in facts');
          $answer = "I don't see any posts in the Hub profile.";
        }
      }
      elseif (preg_match('/\b(update|updates|out of date|outdated)\b/', $lc)) {
        error_log('[Luna Chat] Matched updates pattern');
        $pu = (int)$facts['updates']['plugins']; $tu = (int)$facts['updates']['themes']; $cu = (int)$facts['updates']['core'];
        error_log('[Luna Chat] Updates: plugins=' . $pu . ', themes=' . $tu . ', core=' . $cu);
        $answer = "Updates pending — plugins: ".$pu.", themes: ".$tu.", WordPress Core: ".$cu.".";
      }
      elseif (preg_match('/\b(host|hosting|provider)\b/', $lc)) {
        $h = trim((string)$facts['host']);
        $answer = $h ? ("Hosting provider on file: ".$h.".") : "I don’t have a confirmed hosting provider on file.";
      }
      elseif (preg_match('/\bwordpress\b.*\bversion\b|\bwp\b.*\bversion\b/', $lc)) {
        $v = trim((string)$facts['wp_version']);
        $answer = $v ? ("Your WordPress version is ".$v.".") : "I don't see a confirmed WordPress version in the Hub profile.";
      }
      elseif (preg_match('/\btheme\b.*\bactive\b|\bis.*theme.*active\b/', $lc)) {
        $theme_active = isset($facts['theme_active']) ? (bool)$facts['theme_active'] : true;
        $theme_name = isset($facts['theme']) ? (string)$facts['theme'] : '';
        if ($theme_name) {
          $answer = $theme_active ? ("Yes, the ".$theme_name." theme is currently active.") : ("No, the ".$theme_name." theme is not active.");
        } else {
          $answer = "I don't have confirmation on whether the current theme is active. You may want to check your WordPress dashboard for that information.";
        }
      }
      elseif (preg_match('/\binactive.*theme|theme.*inactive|what.*themes|list.*themes|all.*themes\b/', $lc)) {
        error_log('[Luna Chat] Matched theme list pattern');
        if (isset($facts['themes']) && is_array($facts['themes']) && !empty($facts['themes'])) {
          $active_themes = array();
          $inactive_themes = array();
          foreach ($facts['themes'] as $theme) {
            if (isset($theme['is_active']) && $theme['is_active']) {
              $active_themes[] = $theme['name'] . " (Active)";
            } else {
              $inactive_themes[] = $theme['name'] . " (Inactive)";
            }
          }
          $all_themes = array_merge($active_themes, $inactive_themes);
          $answer = "Your themes are: " . implode(", ", $all_themes) . ".";
        } else {
          $answer = "I don't see any themes in the Hub profile.";
        }
      }
      elseif (preg_match('/\bhow many plugins?\b|\bplugins?\s*(count|total)?\b/', $lc)) {
        $p = isset($facts['counts']['plugins']) ? (int)$facts['counts']['plugins'] : 0;
        $answer = "You currently have ".$p." plugin".($p===1?'':'s')." installed.";
      }
      elseif (preg_match('/\bhttps?\b|\bssl\b|\btls\b/', $lc)) {
        $https = isset($facts['https']) ? (bool)$facts['https'] : false;
        $tls_valid = isset($facts['tls']['valid']) ? (bool)$facts['tls']['valid'] : false;
        if ($https && $tls_valid) {
          $answer = "Yes, your site is using HTTPS with a valid SSL/TLS certificate.";
        } elseif ($https) {
          $answer = "Your site is using HTTPS, but the SSL/TLS certificate status is not confirmed.";
        } else {
          $answer = "Your site is not using HTTPS. Please enable SSL/TLS for security.";
        }
      }

      // AI fallback with facts blended
      if ($answer === '') {
        error_log('[Luna Chat] No regex match found, trying AI fallback');
        $api_key = luna_get_openai_key();
        if ($api_key) {
          error_log('[Luna Chat] OpenAI API key found, making request');
          // Use comprehensive facts for AI fallback
          $comprehensive_facts = luna_profile_facts_comprehensive();
          $messages = luna_openai_messages_with_facts($pid, $prompt, $comprehensive_facts);
          $resp = wp_remote_post('https://api.openai.com/v1/chat/completions', array(
            'timeout' => 20,
            'headers' => array(
              'Authorization' => 'Bearer ' . $api_key,
              'Content-Type'  => 'application/json',
            ),
            'body'    => wp_json_encode(array(
              'model'       => 'gpt-4o-mini',
              'messages'    => $messages,
              'temperature' => 0.2,
              'max_tokens'  => 450,
            )),
          ));
          
          if (is_wp_error($resp)) {
            error_log('[Luna Chat] OpenAI API error: ' . $resp->get_error_message());
          } else {
            $response_code = wp_remote_retrieve_response_code($resp);
            $response_body = wp_remote_retrieve_body($resp);
            error_log('[Luna Chat] OpenAI response code: ' . $response_code);
            error_log('[Luna Chat] OpenAI response body: ' . $response_body);
            
            if ($response_code < 400) {
              $body = json_decode($response_body, true);
            if (is_array($body) && isset($body['choices'][0]['message']['content'])) {
              $answer = (string)$body['choices'][0]['message']['content'];
                error_log('[Luna Chat] AI response: ' . $answer);
              } else {
                error_log('[Luna Chat] Invalid AI response structure');
            }
          }
          }
        } else {
          error_log('[Luna Chat] No OpenAI API key found');
        }
      }

      if ($answer === '') {
        error_log('[Luna Chat] No answer generated, using fallback');
        $answer = "I'm unsure from the current Hub profile. Please verify in your Visible Light client profile.";
      }

      luna_log_turn($prompt, $answer, array('source'=>'widget', 'facts_at'=> isset($facts['generated']) ? $facts['generated'] : null));
      return new WP_REST_Response(array('answer'=>$answer), 200);
    },
  ));

  /* --- HISTORY (hydrate UI after reloads) --- */
  register_rest_route('luna_widget/v1', '/chat/history', array(
    'methods'  => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function( WP_REST_Request $req ){
      $pid = luna_conv_id();
      if (!$pid) return new WP_REST_Response(array('items'=>array()), 200);
      $t = get_post_meta($pid, 'transcript', true); if (!is_array($t)) $t = array();
      $limit = max(1, min(50, (int)$req->get_param('limit') ? (int)$req->get_param('limit') : 20));
      $slice = array_slice($t, -$limit);
      $items = array();
      foreach ($slice as $row) {
        $items[] = array(
          'ts'        => isset($row['ts']) ? (int)$row['ts'] : 0,
          'ts_iso'    => !empty($row['ts']) ? gmdate('c', (int)$row['ts']) : null,
          'user'      => isset($row['user']) ? wp_strip_all_tags((string)$row['user']) : '',
          'assistant' => isset($row['assistant']) ? wp_strip_all_tags((string)$row['assistant']) : '',
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  /* --- Hub-facing list endpoints (license-gated) --- */
  $secure_cb = function(){ return true; };

  // System snapshot (plugins/themes summary here)
  register_rest_route('luna_widget/v1', '/system/site', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      return new WP_REST_Response( luna_snapshot_system(), 200 );
    },
  ));
  // Aliases some hubs expect
  register_rest_route('vl-hub/v1', '/system/site', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      return new WP_REST_Response( luna_snapshot_system(), 200 );
    },
  ));

  // Posts
  $posts_cb = function( WP_REST_Request $req ){
    if (!luna_license_ok($req)) return luna_forbidden();
    $per  = max(1, min(200, (int)$req->get_param('per_page') ?: 50));
    $page = max(1, (int)$req->get_param('page') ?: 1);
    $q = new WP_Query(array(
      'post_type'      => 'post',
      'post_status'    => 'publish',
      'posts_per_page' => $per,
      'paged'          => $page,
      'orderby'        => 'date',
      'order'          => 'DESC',
      'fields'         => 'ids',
    ));
    $items = array();
    foreach ($q->posts as $pid) {
      $cats = wp_get_post_terms($pid, 'category', array('fields'=>'names'));
      $tags = wp_get_post_terms($pid, 'post_tag', array('fields'=>'names'));
      $items[] = array(
        'id'        => $pid,
        'title'     => get_the_title($pid),
        'slug'      => get_post_field('post_name', $pid),
        'date'      => get_post_time('c', true, $pid),
        'author'    => get_the_author_meta('user_login', get_post_field('post_author', $pid)),
        'categories'=> array_values($cats ?: array()),
        'tags'      => array_values($tags ?: array()),
        'permalink' => get_permalink($pid),
      );
    }
    return new WP_REST_Response(array('total'=>(int)$q->found_posts,'page'=>$page,'per_page'=>$per,'items'=>$items), 200);
  };
  register_rest_route('luna_widget/v1', '/content/posts', array('methods'=>'GET','permission_callback'=>$secure_cb,'callback'=>$posts_cb));
  register_rest_route('vl-hub/v1',      '/posts',         array('methods'=>'GET','permission_callback'=>$secure_cb,'callback'=>$posts_cb));

  // Pages
  $pages_cb = function( WP_REST_Request $req ){
    if (!luna_license_ok($req)) return luna_forbidden();
    $per  = max(1, min(200, (int)$req->get_param('per_page') ?: 50));
    $page = max(1, (int)$req->get_param('page') ?: 1);
    $q = new WP_Query(array(
      'post_type'      => 'page',
      'post_status'    => array('publish', 'draft', 'private', 'pending'),
      'posts_per_page' => $per,
      'paged'          => $page,
      'orderby'        => 'date',
      'order'          => 'DESC',
      'fields'         => 'ids',
    ));
    $items = array();
    foreach ($q->posts as $pid) {
      $items[] = array(
        'id'        => $pid,
        'title'     => get_the_title($pid),
        'slug'      => get_post_field('post_name', $pid),
        'status'    => get_post_status($pid),
        'date'      => get_post_time('c', true, $pid),
        'author'    => get_the_author_meta('user_login', get_post_field('post_author', $pid)),
        'permalink' => get_permalink($pid),
      );
    }
    return new WP_REST_Response(array('total'=>(int)$q->found_posts,'page'=>$page,'per_page'=>$per,'items'=>$items), 200);
  };
  register_rest_route('luna_widget/v1', '/content/pages', array('methods'=>'GET','permission_callback'=>$secure_cb,'callback'=>$pages_cb));
  register_rest_route('vl-hub/v1',      '/pages',         array('methods'=>'GET','permission_callback'=>$secure_cb,'callback'=>$pages_cb));

  // Users
  $users_cb = function( WP_REST_Request $req ){
    if (!luna_license_ok($req)) return luna_forbidden();
    $per    = max(1, min(200, (int)$req->get_param('per_page') ?: 100));
    $page   = max(1, (int)$req->get_param('page') ?: 1);
    $offset = ($page-1)*$per;
    $u = get_users(array(
      'number' => $per,
      'offset' => $offset,
      'fields' => array('user_login','user_email','display_name','ID'),
      'orderby'=> 'ID',
      'order'  => 'ASC',
    ));
    $items = array();
    foreach ($u as $row) {
      $items[] = array(
        'id'       => (int)$row->ID,
        'username' => $row->user_login,
        'email'    => $row->user_email,
        'name'     => $row->display_name,
      );
    }
    $counts = count_users();
    $total  = isset($counts['total_users']) ? (int)$counts['total_users'] : (int)($offset + count($items));
    return new WP_REST_Response(array('total'=>$total,'page'=>$page,'per_page'=>$per,'items'=>$items), 200);
  };
  register_rest_route('luna_widget/v1', '/users', array('methods'=>'GET','permission_callback'=>$secure_cb,'callback'=>$users_cb));
  register_rest_route('vl-hub/v1',      '/users', array('methods'=>'GET','permission_callback'=>$secure_cb,'callback'=>$users_cb));

  // Plugins
  register_rest_route('luna_widget/v1', '/plugins', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      if (!function_exists('get_plugins')) { @require_once ABSPATH . 'wp-admin/includes/plugin.php'; }
      $plugins = function_exists('get_plugins') ? (array)get_plugins() : array();
      $active  = (array) get_option('active_plugins', array());
      $up_pl   = get_site_transient('update_plugins');
      $items = array();
      foreach ($plugins as $slug => $info) {
        $update_available = isset($up_pl->response[$slug]);
        $items[] = array(
          'slug'            => $slug,
          'name'            => isset($info['Name']) ? $info['Name'] : $slug,
          'version'         => isset($info['Version']) ? $info['Version'] : null,
          'active'          => in_array($slug, $active, true),
          'update_available'=> (bool)$update_available,
          'new_version'     => $update_available ? (isset($up_pl->response[$slug]->new_version) ? $up_pl->response[$slug]->new_version : null) : null,
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  // Themes
  register_rest_route('luna_widget/v1', '/themes', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      $themes = wp_get_themes();
      $up_th  = get_site_transient('update_themes');
      $active_stylesheet = wp_get_theme()->get_stylesheet();
      $items = array();
      foreach ($themes as $stylesheet => $th) {
        $update_available = isset($up_th->response[$stylesheet]);
        $items[] = array(
          'stylesheet'      => $stylesheet,
          'name'            => $th->get('Name'),
          'version'         => $th->get('Version'),
          'is_active'       => ($active_stylesheet === $stylesheet),
          'update_available'=> (bool)$update_available,
          'new_version'     => $update_available ? (isset($up_th->response[$stylesheet]['new_version']) ? $up_th->response[$stylesheet]['new_version'] : null) : null,
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  /* Utilities: manual pings */
  register_rest_route('luna_widget/v1', '/ping-hub', array(
    'methods'  => 'POST',
    'permission_callback' => function(){ return current_user_can('manage_options'); },
    'callback' => function(){
      luna_widget_try_activation();
      $last = get_option(LUNA_WIDGET_OPT_LAST_PING, array());
      return new WP_REST_Response(array('ok'=>true,'last'=>$last), 200);
    },
  ));
  register_rest_route('luna_widget/v1', '/heartbeat-now', array(
    'methods'  => 'POST',
    'permission_callback' => function(){ return current_user_can('manage_options'); },
    'callback' => function(){
      luna_widget_send_heartbeat();
      $last = get_option(LUNA_WIDGET_OPT_LAST_PING, array());
      return new WP_REST_Response(array('ok'=>true,'last'=>$last), 200);
    },
  ));

  /* --- Purge profile cache (Hub → client after Security edits) --- */
  register_rest_route('luna_widget/v1', '/purge-profile-cache', array(
    'methods'  => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      if (!luna_license_ok($req)) return new WP_REST_Response(array('ok'=>false,'error'=>'forbidden'), 403);
      luna_profile_cache_bust(true);
      return new WP_REST_Response(array('ok'=>true,'message'=>'Profile cache purged'), 200);
    },
  ));

  /* --- Debug endpoint to test Hub connection --- */
  register_rest_route('luna_widget/v1', '/debug-hub', array(
    'methods'  => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = luna_get_license();
      $hub_url = luna_widget_hub_base();
      $endpoint = $hub_url . '/wp-json/luna_widget/v1/system/comprehensive';
      
      $response = wp_remote_get($endpoint, array(
        'headers' => array('X-Luna-License' => $license),
        'timeout' => 10
      ));
      
      $debug_info = array(
        'license' => $license ? substr($license, 0, 8) . '...' : 'NOT SET',
        'hub_url' => $hub_url,
        'endpoint' => $endpoint,
        'is_error' => is_wp_error($response),
        'error_message' => is_wp_error($response) ? $response->get_error_message() : null,
        'response_code' => is_wp_error($response) ? null : wp_remote_retrieve_response_code($response),
        'response_body' => is_wp_error($response) ? null : wp_remote_retrieve_body($response),
      );
      
      return new WP_REST_Response($debug_info, 200);
    },
  ));

  /* --- Debug endpoint to see comprehensive facts --- */
  register_rest_route('luna_widget/v1', '/debug-facts', array(
    'methods'  => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $facts = luna_profile_facts_comprehensive();
      
      $debug_info = array(
        'comprehensive_facts' => $facts,
        'has_pages' => isset($facts['pages']) && is_array($facts['pages']) ? count($facts['pages']) : 0,
        'has_themes' => isset($facts['themes']) && is_array($facts['themes']) ? count($facts['themes']) : 0,
        'updates' => $facts['updates'] ?? array(),
        'counts' => $facts['counts'] ?? array(),
      );
      
      return new WP_REST_Response($debug_info, 200);
    },
  ));

  /* --- Debug endpoint to test regex patterns --- */
  register_rest_route('luna_widget/v1', '/debug-regex', array(
    'methods'  => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $test_phrases = array(
        'What are the names of the pages?',
        'What are the names of the posts?',
        'Do I have any inactive pages?',
        'What themes do I have?'
      );
      
      $results = array();
      foreach ($test_phrases as $phrase) {
        $lc = strtolower($phrase);
        $results[$phrase] = array(
          'lowercase' => $lc,
          'page_names_match' => preg_match('/\bnames.*of.*pages|page.*names|what.*are.*the.*names.*of.*pages\b/', $lc),
          'post_names_match' => preg_match('/\bnames.*of.*posts|post.*names|what.*are.*the.*names.*of.*posts\b/', $lc),
          'inactive_pages_match' => preg_match('/\binactive.*page|page.*inactive|draft.*page|page.*draft\b/', $lc),
          'theme_list_match' => preg_match('/\binactive.*theme|theme.*inactive|what.*themes|list.*themes|all.*themes\b/', $lc)
        );
      }
      
      return new WP_REST_Response($results, 200);
    },
  ));

  /* --- Debug endpoint for keyword mappings --- */
  register_rest_route('luna_widget/v1', '/debug-keywords', array(
    'methods'  => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $test_input = $req->get_param('input') ?: 'hey Lu';
      $mappings = luna_get_keyword_mappings();
      $keyword_match = luna_check_keyword_mappings($test_input);
      
      return new WP_REST_Response(array(
        'test_input' => $test_input,
        'mappings' => $mappings,
        'keyword_match' => $keyword_match,
        'mapping_count' => count($mappings)
      ), 200);
    },
  ));
});

/* ============================================================
 * KEYWORD MAPPING SYSTEM
 * ============================================================ */

// Default keyword mappings with response templates
function luna_get_default_keywords() {
  return [
    'business' => [
      'appointment' => [
        'enabled' => 'on',
        'keywords' => ['booking', 'schedule', 'visit', 'consultation'],
        'template' => 'To schedule an appointment, please call our office or use our online booking system. You can find our contact information on our website.',
        'data_source' => 'custom'
      ],
      'contact' => [
        'enabled' => 'on',
        'keywords' => ['phone', 'email', 'reach', 'get in touch'],
        'template' => 'You can reach us through our contact page or by calling our main office number. Our contact information is available on our website.',
        'data_source' => 'custom'
      ],
      'hours' => [
        'enabled' => 'on',
        'keywords' => ['open', 'closed', 'business hours', 'availability'],
        'template' => 'Our business hours are typically Monday through Friday, 9 AM to 5 PM. Please check our website for the most current hours and holiday schedules.',
        'data_source' => 'custom'
      ],
      'location' => [
        'enabled' => 'on',
        'keywords' => ['address', 'where', 'directions', 'find us'],
        'template' => 'You can find our address and directions on our website\'s contact page. We\'re located in a convenient area with parking available.',
        'data_source' => 'custom'
      ],
      'services' => [
        'enabled' => 'on',
        'keywords' => ['what we do', 'offerings', 'treatments', 'care'],
        'template' => 'We offer a comprehensive range of services. Please visit our services page on our website for detailed information about what we provide.',
        'data_source' => 'custom'
      ],
      'providers' => [
        'enabled' => 'on',
        'keywords' => ['doctors', 'staff', 'team', 'physicians'],
        'template' => 'Our team of experienced providers is dedicated to your care. You can learn more about our staff on our website\'s team page.',
        'data_source' => 'custom'
      ],
      'insurance' => [
        'enabled' => 'on',
        'keywords' => ['coverage', 'accepted', 'billing', 'payment'],
        'template' => 'We accept most major insurance plans. Please contact our billing department to verify your coverage and discuss payment options.',
        'data_source' => 'custom'
      ],
      'forms' => [
        'enabled' => 'on',
        'keywords' => ['paperwork', 'documents', 'download', 'patient forms'],
        'template' => 'You can download patient forms from our website or pick them up at our office. Please complete them before your visit to save time.',
        'data_source' => 'custom'
      ]
    ],
    'wp_rest' => [
      'pages' => [
        'enabled' => 'on',
        'keywords' => ['page names', 'what pages', 'list pages', 'site pages'],
        'template' => 'Your pages are: {pages_list}.',
        'data_source' => 'wp_rest'
      ],
      'posts' => [
        'enabled' => 'on',
        'keywords' => ['blog posts', 'articles', 'news', 'content'],
        'template' => 'Your posts are: {posts_list}.',
        'data_source' => 'wp_rest'
      ],
      'themes' => [
        'enabled' => 'on',
        'keywords' => ['theme info', 'design', 'appearance', 'look'],
        'template' => 'Your themes are: {themes_list}.',
        'data_source' => 'wp_rest'
      ],
      'plugins' => [
        'enabled' => 'on',
        'keywords' => ['add-ons', 'extensions', 'tools', 'features'],
        'template' => 'Your plugins are: {plugins_list}.',
        'data_source' => 'wp_rest'
      ],
      'users' => [
        'enabled' => 'on',
        'keywords' => ['admin', 'administrators', 'who can login'],
        'template' => 'You have {user_count} user{user_plural} with access to your site.',
        'data_source' => 'wp_rest'
      ],
      'updates' => [
        'enabled' => 'on',
        'keywords' => ['outdated', 'new version', 'upgrade', 'patches'],
        'template' => 'Updates pending — plugins: {plugin_updates}, themes: {theme_updates}, WordPress Core: {core_updates}.',
        'data_source' => 'wp_rest'
      ],
      'media' => [
        'enabled' => 'on',
        'keywords' => ['images', 'files', 'uploads', 'gallery'],
        'template' => 'Media information is available in your WordPress dashboard under Media.',
        'data_source' => 'custom'
      ]
    ],
    'security' => [
      'ssl' => [
        'enabled' => 'on',
        'keywords' => ['certificate', 'https', 'secure', 'encrypted'],
        'template' => '{ssl_status}',
        'data_source' => 'security'
      ],
      'firewall' => [
        'enabled' => 'on',
        'keywords' => ['protection', 'security', 'blocking', 'defense'],
        'template' => 'Firewall protection status is available in your security settings. Please check the Security tab in Visible Light for detailed firewall information.',
        'data_source' => 'security'
      ],
      'backup' => [
        'enabled' => 'on',
        'keywords' => ['backup', 'restore', 'recovery', 'safety'],
        'template' => 'Backup information is available in your security profile. Please check the Security tab in Visible Light for backup status and schedules.',
        'data_source' => 'security'
      ],
      'monitoring' => [
        'enabled' => 'on',
        'keywords' => ['scan', 'threats', 'vulnerabilities', 'alerts'],
        'template' => 'Security monitoring details are available in your security profile. Please check the Security tab in Visible Light for scan results and alerts.',
        'data_source' => 'security'
      ],
      'access' => [
        'enabled' => 'on',
        'keywords' => ['login', 'authentication', 'permissions', 'users'],
        'template' => 'You have {user_count} user{user_plural} with access to your site.',
        'data_source' => 'wp_rest'
      ],
      'compliance' => [
        'enabled' => 'on',
        'keywords' => ['hipaa', 'gdpr', 'standards', 'regulations'],
        'template' => 'Compliance information is available in your security profile. Please check the Security tab in Visible Light for compliance status and requirements.',
        'data_source' => 'security'
      ]
    ]
  ];
}

// Get current keyword mappings
function luna_get_keyword_mappings() {
  $custom = get_option('luna_keyword_mappings', []);
  
  // If we have custom data, return it directly
  if (!empty($custom)) {
    return $custom;
  }
  
  // Otherwise, return defaults
  return luna_get_default_keywords();
}

// Save keyword mappings
function luna_save_keyword_mappings($mappings) {
  // Debug: Log what's being processed
  error_log('Luna Keywords: Processing mappings: ' . print_r($mappings, true));
  
  // Process the new data structure
  $processed_mappings = array();
  
  foreach ($mappings as $category => $actions) {
    foreach ($actions as $action => $config) {
      // Skip if no keywords or empty config
      if (empty($config['keywords']) || !is_array($config['keywords'])) {
        continue;
      }
      
      $processed_config = array(
        'enabled' => $config['enabled'] ?? 'on',
        'keywords' => $config['keywords'] ?? array(),
        'data_source' => $config['data_source'] ?? 'custom',
        'response_type' => $config['response_type'] ?? 'simple'
      );
      
      // Only process active keywords for template processing
      if ($processed_config['enabled'] === 'on') {
        // Handle different data sources
        switch ($config['data_source']) {
          case 'wp_rest':
            $processed_config['wp_template'] = $config['wp_template'] ?? '';
            break;
          case 'security':
            $processed_config['security_template'] = $config['security_template'] ?? '';
            break;
          case 'custom':
          default:
            if ($config['response_type'] === 'advanced') {
              $processed_config['initial_response'] = $config['initial_response'] ?? '';
              $processed_config['branches'] = $config['branches'] ?? array();
            } else {
              $processed_config['template'] = $config['template'] ?? '';
            }
            break;
        }
      } else {
        // For disabled keywords, just store basic info without templates
        error_log("Luna Keywords: Storing disabled keyword - {$category}.{$action}");
      }
      
      $processed_mappings[$category][$action] = $processed_config;
    }
  }
  
  // Debug: Log what's being stored
  error_log('Luna Keywords: Final processed mappings: ' . print_r($processed_mappings, true));
  
  // Visual debug - show what's being processed
  echo '<div class="notice notice-info"><p><strong>DEBUG:</strong> Final processed mappings: ' . esc_html(print_r($processed_mappings, true)) . '</p></div>';
  
  update_option('luna_keyword_mappings', $processed_mappings);
  
  // Debug: Verify what was stored
  $stored = get_option('luna_keyword_mappings', array());
  error_log('Luna Keywords: Verified stored data: ' . print_r($stored, true));
  
  // Visual debug - show what was stored
  echo '<div class="notice notice-info"><p><strong>DEBUG:</strong> Verified stored data: ' . esc_html(print_r($stored, true)) . '</p></div>';
  
  // Send to Hub
  luna_sync_keywords_to_hub($processed_mappings);
}

// Sync keywords to Hub
function luna_sync_keywords_to_hub($mappings) {
  $license = luna_get_license();
  if (!$license) return;
  
  $response = wp_remote_post('https://visiblelight.ai/wp-json/luna_widget/v1/keywords/sync', [
    'timeout' => 10,
    'headers' => ['X-Luna-License' => $license, 'Content-Type' => 'application/json'],
    'body' => json_encode(['keywords' => $mappings])
  ]);
  
  if (is_wp_error($response)) {
    error_log('[Luna] Failed to sync keywords to Hub: ' . $response->get_error_message());
  }
}

// Track keyword usage and performance
function luna_track_keyword_usage($keyword_match, $response_success = true) {
  $usage_stats = get_option('luna_keyword_usage', []);
  
  $key = $keyword_match['category'] . '.' . $keyword_match['action'];
  
  if (!isset($usage_stats[$key])) {
    $usage_stats[$key] = [
      'total_uses' => 0,
      'successful_uses' => 0,
      'failed_uses' => 0,
      'last_used' => current_time('mysql'),
      'keywords' => $keyword_match['matched_term']
    ];
  }
  
  $usage_stats[$key]['total_uses']++;
  $usage_stats[$key]['last_used'] = current_time('mysql');
  
  if ($response_success) {
    $usage_stats[$key]['successful_uses']++;
  } else {
    $usage_stats[$key]['failed_uses']++;
  }
  
  update_option('luna_keyword_usage', $usage_stats);
}

// Get keyword performance statistics
function luna_get_keyword_performance() {
  $usage_stats = get_option('luna_keyword_usage', []);
  $performance = [];
  
  foreach ($usage_stats as $key => $stats) {
    $success_rate = $stats['total_uses'] > 0 ? ($stats['successful_uses'] / $stats['total_uses']) * 100 : 0;
    
    $performance[$key] = [
      'total_uses' => $stats['total_uses'],
      'success_rate' => round($success_rate, 1),
      'last_used' => $stats['last_used'],
      'keywords' => $stats['keywords']
    ];
  }
  
  // Sort by total uses (most popular first)
  uasort($performance, function($a, $b) {
    return $b['total_uses'] - $a['total_uses'];
  });
  
  return $performance;
}

// Check if user input matches any keywords
function luna_check_keyword_mappings($user_input) {
  $mappings = luna_get_keyword_mappings();
  $lc_input = strtolower(trim($user_input));
  
  // Debug: Log what we're checking
  error_log('Luna Keywords: Checking input: "' . $lc_input . '"');
  
  foreach ($mappings as $category => $keywords) {
    foreach ($keywords as $action => $config) {
      // Skip disabled keywords
      if (isset($config['enabled']) && $config['enabled'] !== 'on') {
        continue;
      }
      
      // Handle both old format (array of terms) and new format (config object)
      $terms = is_array($config) && isset($config['keywords']) ? $config['keywords'] : $config;
      
      if (!is_array($terms)) {
        continue;
      }
      
      foreach ($terms as $term) {
        $lc_term = strtolower(trim($term));
        if (empty($lc_term)) continue;
        
        // Use word boundary matching for more precise matching
        if (preg_match('/\b' . preg_quote($lc_term, '/') . '\b/', $lc_input)) {
          error_log('Luna Keywords: Matched term "' . $lc_term . '" for ' . $category . '.' . $action);
          return [
            'category' => $category,
            'action' => $action,
            'matched_term' => $term,
            'config' => is_array($config) && isset($config['template']) ? $config : null
          ];
        }
      }
    }
  }
  
  error_log('Luna Keywords: No keyword matches found');
  return null;
}

// Handle keyword-based responses using templates
function luna_handle_keyword_response($keyword_match, $facts) {
  $category = $keyword_match['category'];
  $action = $keyword_match['action'];
  $matched_term = $keyword_match['matched_term'];
  $config = $keyword_match['config'];
  
  // If we have a template config, use it
  if ($config) {
    $data_source = $config['data_source'] ?? 'custom';
    $response_type = $config['response_type'] ?? 'simple';
    
    switch ($data_source) {
      case 'wp_rest':
        return luna_process_response_template($config['wp_template'] ?? '', 'wp_rest', $facts);
      case 'security':
        return luna_process_response_template($config['security_template'] ?? '', 'security', $facts);
      case 'custom':
      default:
        if ($response_type === 'advanced') {
          // For advanced responses, we'll return the initial response
          // The branching logic would be handled in a more complex conversation flow
          return luna_process_response_template($config['initial_response'] ?? '', 'custom', $facts);
        } else {
          return luna_process_response_template($config['template'] ?? '', 'custom', $facts);
        }
    }
  }
  
  // Fallback to old system for backward compatibility
  switch ($category) {
    case 'business':
      return luna_handle_business_keyword($action, $facts);
      
    case 'wp_rest':
      return luna_handle_wp_rest_keyword($action, $facts);
      
    case 'security':
      return luna_handle_security_keyword($action, $facts);
      
    default:
      return null;
  }
}

// Process response templates with dynamic data
function luna_process_response_template($template, $data_source, $facts) {
  $response = $template;
  
  // Replace template variables based on data source
  switch ($data_source) {
    case 'wp_rest':
      $response = luna_replace_wp_rest_variables($response, $facts);
      break;
      
    case 'security':
      $response = luna_replace_security_variables($response, $facts);
      break;
      
    case 'custom':
      $response = luna_replace_custom_shortcodes($response, $facts);
      break;
  }
  
  return $response;
}

// Replace WP REST API variables in templates
function luna_replace_wp_rest_variables($template, $facts) {
  $replacements = [];
  
  // Pages list
  if (strpos($template, '{pages_list}') !== false) {
    if (isset($facts['pages']) && is_array($facts['pages']) && !empty($facts['pages'])) {
      $page_names = array();
      foreach ($facts['pages'] as $page) {
        $status = isset($page['status']) ? $page['status'] : 'published';
        $page_names[] = $page['title'] . " (" . $status . ")";
      }
      $replacements['{pages_list}'] = implode(", ", $page_names);
    } else {
      $replacements['{pages_list}'] = "No pages found";
    }
  }
  
  // Posts list
  if (strpos($template, '{posts_list}') !== false) {
    if (isset($facts['posts']) && is_array($facts['posts']) && !empty($facts['posts'])) {
      $post_names = array();
      foreach ($facts['posts'] as $post) {
        $status = isset($post['status']) ? $post['status'] : 'published';
        $post_names[] = $post['title'] . " (" . $status . ")";
      }
      $replacements['{posts_list}'] = implode(", ", $post_names);
    } else {
      $replacements['{posts_list}'] = "No posts found";
    }
  }
  
  // Themes list
  if (strpos($template, '{themes_list}') !== false) {
    if (isset($facts['themes']) && is_array($facts['themes']) && !empty($facts['themes'])) {
      $active_themes = array();
      $inactive_themes = array();
      foreach ($facts['themes'] as $theme) {
        if (isset($theme['is_active']) && $theme['is_active']) {
          $active_themes[] = $theme['name'] . " (Active)";
        } else {
          $inactive_themes[] = $theme['name'] . " (Inactive)";
        }
      }
      $all_themes = array_merge($active_themes, $inactive_themes);
      $replacements['{themes_list}'] = implode(", ", $all_themes);
    } else {
      $replacements['{themes_list}'] = "No themes found";
    }
  }
  
  // Plugins list
  if (strpos($template, '{plugins_list}') !== false) {
    if (isset($facts['plugins']) && is_array($facts['plugins']) && !empty($facts['plugins'])) {
      $plugin_names = array();
      foreach ($facts['plugins'] as $plugin) {
        $status = isset($plugin['active']) && $plugin['active'] ? 'Active' : 'Inactive';
        $plugin_names[] = $plugin['name'] . " (" . $status . ")";
      }
      $replacements['{plugins_list}'] = implode(", ", $plugin_names);
    } else {
      $replacements['{plugins_list}'] = "No plugins found";
    }
  }
  
  // User count
  if (strpos($template, '{user_count}') !== false) {
    $user_count = isset($facts['users']) && is_array($facts['users']) ? count($facts['users']) : 0;
    $replacements['{user_count}'] = $user_count;
    $replacements['{user_plural}'] = $user_count === 1 ? '' : 's';
  }
  
  // Update counts
  if (strpos($template, '{plugin_updates}') !== false) {
    $replacements['{plugin_updates}'] = (int)($facts['updates']['plugins'] ?? 0);
  }
  if (strpos($template, '{theme_updates}') !== false) {
    $replacements['{theme_updates}'] = (int)($facts['updates']['themes'] ?? 0);
  }
  if (strpos($template, '{core_updates}') !== false) {
    $replacements['{core_updates}'] = (int)($facts['updates']['core'] ?? 0);
  }
  
  // Apply all replacements
  foreach ($replacements as $placeholder => $value) {
    $template = str_replace($placeholder, $value, $template);
  }
  
  return $template;
}

// Replace security variables in templates
function luna_replace_security_variables($template, $facts) {
  if (strpos($template, '{ssl_status}') !== false) {
    if (!empty($facts['tls']['valid'])) {
      $extras = array();
      if (!empty($facts['tls']['issuer'])) $extras[] = "issuer: " . $facts['tls']['issuer'];
      if (!empty($facts['tls']['expires'])) $extras[] = "expires: " . $facts['tls']['expires'];
      $ssl_status = "Yes—TLS/SSL is active for " . $facts['site_url'] . ($extras ? " (" . implode(', ', $extras) . ")." : ".");
    } else {
      $ssl_status = "Hub shows TLS/SSL is not confirmed active for " . $facts['site_url'] . ". Please review the Security tab in Visible Light.";
    }
    $template = str_replace('{ssl_status}', $ssl_status, $template);
  }
  
  return $template;
}

// Replace custom shortcodes in templates
function luna_replace_custom_shortcodes($template, $facts) {
  $replacements = [];
  
  // Contact page link
  if (strpos($template, '[contact_page]') !== false) {
    $contact_url = get_permalink(get_page_by_path('contact'));
    if (!$contact_url) {
      $contact_url = home_url('/contact/');
    }
    $replacements['[contact_page]'] = '<a href="' . esc_url($contact_url) . '" target="_blank">Contact Page</a>';
  }
  
  // Booking link
  if (strpos($template, '[booking_link]') !== false) {
    $booking_url = get_permalink(get_page_by_path('book'));
    if (!$booking_url) {
      $booking_url = home_url('/book/');
    }
    $replacements['[booking_link]'] = '<a href="' . esc_url($booking_url) . '" target="_blank">Book Appointment</a>';
  }
  
  // Phone number
  if (strpos($template, '[phone_number]') !== false) {
    $phone = get_option('luna_business_phone', '(555) 123-4567');
    $replacements['[phone_number]'] = '<a href="tel:' . esc_attr($phone) . '">' . esc_html($phone) . '</a>';
  }
  
  // Email link
  if (strpos($template, '[email_link]') !== false) {
    $email = get_option('luna_business_email', 'info@example.com');
    $replacements['[email_link]'] = '<a href="mailto:' . esc_attr($email) . '">' . esc_html($email) . '</a>';
  }
  
  // Site URL
  if (strpos($template, '[site_url]') !== false) {
    $replacements['[site_url]'] = '<a href="' . esc_url(home_url()) . '" target="_blank">' . esc_html(get_bloginfo('name')) . '</a>';
  }
  
  // Business name
  if (strpos($template, '[business_name]') !== false) {
    $business_name = get_option('luna_business_name', get_bloginfo('name'));
    $replacements['[business_name]'] = esc_html($business_name);
  }
  
  return str_replace(array_keys($replacements), array_values($replacements), $template);
}

// Handle business-specific keywords
function luna_handle_business_keyword($action, $facts) {
  switch ($action) {
    case 'appointment':
      return "To schedule an appointment, please call our office or use our online booking system. You can find our contact information on our website.";
      
    case 'contact':
      return "You can reach us through our contact page or by calling our main office number. Our contact information is available on our website.";
      
    case 'hours':
      return "Our business hours are typically Monday through Friday, 9 AM to 5 PM. Please check our website for the most current hours and holiday schedules.";
      
    case 'location':
      return "You can find our address and directions on our website's contact page. We're located in a convenient area with parking available.";
      
    case 'services':
      return "We offer a comprehensive range of services. Please visit our services page on our website for detailed information about what we provide.";
      
    case 'providers':
      return "Our team of experienced providers is dedicated to your care. You can learn more about our staff on our website's team page.";
      
    case 'insurance':
      return "We accept most major insurance plans. Please contact our billing department to verify your coverage and discuss payment options.";
      
    case 'forms':
      return "You can download patient forms from our website or pick them up at our office. Please complete them before your visit to save time.";
      
    default:
      return null;
  }
}

// Handle WP REST API keywords
function luna_handle_wp_rest_keyword($action, $facts) {
  switch ($action) {
    case 'pages':
      if (isset($facts['pages']) && is_array($facts['pages']) && !empty($facts['pages'])) {
        $page_names = array();
        foreach ($facts['pages'] as $page) {
          $status = isset($page['status']) ? $page['status'] : 'published';
          $page_names[] = $page['title'] . " (" . $status . ")";
        }
        return "Your pages are: " . implode(", ", $page_names) . ".";
      }
      return "I don't see any pages in your site data.";
      
    case 'posts':
      if (isset($facts['posts']) && is_array($facts['posts']) && !empty($facts['posts'])) {
        $post_names = array();
        foreach ($facts['posts'] as $post) {
          $status = isset($post['status']) ? $post['status'] : 'published';
          $post_names[] = $post['title'] . " (" . $status . ")";
        }
        return "Your posts are: " . implode(", ", $post_names) . ".";
      }
      return "I don't see any posts in your site data.";
      
    case 'themes':
      if (isset($facts['themes']) && is_array($facts['themes']) && !empty($facts['themes'])) {
        $active_themes = array();
        $inactive_themes = array();
        foreach ($facts['themes'] as $theme) {
          if (isset($theme['is_active']) && $theme['is_active']) {
            $active_themes[] = $theme['name'] . " (Active)";
          } else {
            $inactive_themes[] = $theme['name'] . " (Inactive)";
          }
        }
        $all_themes = array_merge($active_themes, $inactive_themes);
        return "Your themes are: " . implode(", ", $all_themes) . ".";
      }
      return "I don't see any themes in your site data.";
      
    case 'plugins':
      if (isset($facts['plugins']) && is_array($facts['plugins']) && !empty($facts['plugins'])) {
        $plugin_names = array();
        foreach ($facts['plugins'] as $plugin) {
          $status = isset($plugin['active']) && $plugin['active'] ? 'Active' : 'Inactive';
          $plugin_names[] = $plugin['name'] . " (" . $status . ")";
        }
        return "Your plugins are: " . implode(", ", $plugin_names) . ".";
      }
      return "I don't see any plugins in your site data.";
      
    case 'updates':
      $pu = (int)($facts['updates']['plugins'] ?? 0);
      $tu = (int)($facts['updates']['themes'] ?? 0);
      $cu = (int)($facts['updates']['core'] ?? 0);
      return "Updates pending — plugins: " . $pu . ", themes: " . $tu . ", WordPress Core: " . $cu . ".";
      
    default:
      return null;
  }
}

// Handle security keywords
function luna_handle_security_keyword($action, $facts) {
  switch ($action) {
    case 'ssl':
      if (!empty($facts['tls']['valid'])) {
        $extras = array();
        if (!empty($facts['tls']['issuer'])) $extras[] = "issuer: " . $facts['tls']['issuer'];
        if (!empty($facts['tls']['expires'])) $extras[] = "expires: " . $facts['tls']['expires'];
        return "Yes—TLS/SSL is active for " . $facts['site_url'] . ($extras ? " (" . implode(', ', $extras) . ")." : ".");
      }
      return "Hub shows TLS/SSL is not confirmed active for " . $facts['site_url'] . ". Please review the Security tab in Visible Light.";
      
    case 'firewall':
      return "Firewall protection status is available in your security settings. Please check the Security tab in Visible Light for detailed firewall information.";
      
    case 'backup':
      return "Backup information is available in your security profile. Please check the Security tab in Visible Light for backup status and schedules.";
      
    case 'monitoring':
      return "Security monitoring details are available in your security profile. Please check the Security tab in Visible Light for scan results and alerts.";
      
    case 'access':
      if (isset($facts['users']) && is_array($facts['users']) && !empty($facts['users'])) {
        $user_count = count($facts['users']);
        return "You have " . $user_count . " user" . ($user_count === 1 ? '' : 's') . " with access to your site.";
      }
      return "User access information is available in your security profile.";
      
    case 'compliance':
      return "Compliance information is available in your security profile. Please check the Security tab in Visible Light for compliance status and requirements.";
      
    default:
      return null;
  }
}

// Keywords admin page with enhanced template system
function luna_widget_keywords_admin_page() {
  if (isset($_POST['save_keywords'])) {
    check_admin_referer('luna_keywords_nonce');
    
    // Debug: Show what's being submitted (temporarily disabled)
    // echo '<div style="background: #e7f3ff; padding: 10px; margin: 10px 0; border: 1px solid #0073aa;">';
    // echo '<h4>Debug: POST Data Received</h4>';
    // echo '<pre>' . print_r($_POST, true) . '</pre>';
    // echo '</div>';
    
    // Process the form data properly
    if (isset($_POST['keywords'])) {
      $processed_keywords = array();
      
      foreach ($_POST['keywords'] as $category => $actions) {
        $processed_keywords[$category] = array();
        
        foreach ($actions as $action => $config) {
          // Skip if no keywords provided
          if (empty($config['keywords'])) {
            continue;
          }
          
          // Process keywords - split by comma and trim
          $keywords_array = array_map('trim', explode(',', $config['keywords']));
          $keywords_array = array_filter($keywords_array); // Remove empty values
          
          if (empty($keywords_array)) {
            continue;
          }
          
          $processed_config = array(
            'enabled' => isset($config['enabled']) ? 'on' : 'off',
            'keywords' => $keywords_array,
            'template' => sanitize_textarea_field($config['template'] ?? ''),
            'data_source' => sanitize_text_field($config['data_source'] ?? 'custom'),
            'response_type' => sanitize_text_field($config['response_type'] ?? 'simple')
          );
          
          // Add additional fields if they exist
          if (isset($config['wp_template'])) {
            $processed_config['wp_template'] = sanitize_textarea_field($config['wp_template']);
          }
          if (isset($config['security_template'])) {
            $processed_config['security_template'] = sanitize_textarea_field($config['security_template']);
          }
          if (isset($config['initial_response'])) {
            $processed_config['initial_response'] = sanitize_textarea_field($config['initial_response']);
          }
          if (isset($config['branches'])) {
            $processed_config['branches'] = $config['branches'];
          }
          
          $processed_keywords[$category][$action] = $processed_config;
        }
      }
      
      // Save the processed keywords
      update_option('luna_keyword_mappings', $processed_keywords);
      
      // Debug: Show what was saved (temporarily disabled)
      // echo '<div style="background: #d4edda; padding: 10px; margin: 10px 0; border: 1px solid #c3e6cb;">';
      // echo '<h4>Debug: Processed and Saved Keywords</h4>';
      // echo '<pre>' . print_r($processed_keywords, true) . '</pre>';
      // echo '</div>';
      
      // Sync to Hub
      luna_sync_keywords_to_hub();
      
      echo '<div class="notice notice-success"><p>Keywords saved and synced to Hub!</p></div>';
    }
  }
  
  // Load mappings for display - merge with defaults to show all keywords
  $saved_mappings = get_option('luna_keyword_mappings', []);
  $default_mappings = luna_get_default_keywords();
  $mappings = [];
  
  // Start with defaults
  foreach ($default_mappings as $category => $keywords) {
    $mappings[$category] = [];
    foreach ($keywords as $action => $default_config) {
      // Use saved data if it exists, otherwise use default
      if (isset($saved_mappings[$category][$action])) {
        $mappings[$category][$action] = $saved_mappings[$category][$action];
      } else {
        $mappings[$category][$action] = $default_config;
      }
    }
  }
  
  // Add any custom keywords that aren't in defaults
  foreach ($saved_mappings as $category => $keywords) {
    if (!isset($mappings[$category])) {
      $mappings[$category] = [];
    }
    foreach ($keywords as $action => $config) {
      if (!isset($mappings[$category][$action])) {
        $mappings[$category][$action] = $config;
      }
    }
  }
  
  // Debug: Show what we're working with (temporarily disabled)
  // echo '<div style="background: #f0f0f0; padding: 10px; margin: 10px 0; border: 1px solid #ccc;">';
  // echo '<h4>Debug: Current Mappings</h4>';
  // echo '<pre>' . print_r($mappings, true) . '</pre>';
  // echo '</div>';
  ?>
    <div class="wrap">
      <h1>Luna Chat Keywords & Templates</h1>
      <p>Configure keyword mappings and response templates to help Luna understand your business terminology and respond more accurately.</p>
      
      <div style="margin: 20px 0;">
        <button type="button" id="add-new-keyword" class="button button-primary">+ Add New Keyword</button>
        <button type="button" id="add-new-category" class="button">+ Add New Category</button>
        <button type="button" id="manage-keywords" class="button">Manage Existing Keywords</button>
      </div>
      
      <!-- Modal for adding new keyword -->
      <div id="keyword-modal" class="luna-modal" style="display: none;">
        <div class="luna-modal-content">
          <div class="luna-modal-header">
            <h2>Add New Keyword</h2>
            <span class="luna-modal-close">&times;</span>
          </div>
          <div class="luna-modal-body">
            <table class="form-table">
              <tr>
                <th scope="row">Category</th>
                <td>
                  <select id="new-keyword-category" class="regular-text">
                    <option value="business">Business</option>
                    <option value="wp_rest">WordPress Data</option>
                    <option value="security">Security</option>
                    <option value="custom">Custom</option>
                  </select>
                  <p class="description">Select the category for this keyword</p>
                </td>
              </tr>
              <tr>
                <th scope="row">Keyword Name</th>
                <td>
                  <input type="text" id="new-keyword-name" class="regular-text" placeholder="e.g., pricing, hours, support">
                  <p class="description">Enter a unique name for this keyword</p>
                </td>
              </tr>
              <tr>
                <th scope="row">Keywords</th>
                <td>
                  <input type="text" id="new-keyword-terms" class="regular-text" placeholder="Enter keywords separated by commas">
                  <p class="description">Words or phrases that will trigger this response</p>
                </td>
              </tr>
              <tr>
                <th scope="row">Data Source</th>
                <td>
                  <select id="new-keyword-data-source" class="regular-text">
                    <option value="custom">Custom Response</option>
                    <option value="wp_rest">WordPress Data</option>
                    <option value="security">Security Data</option>
                  </select>
                </td>
              </tr>
              <tr>
                <th scope="row">Response Template</th>
                <td>
                  <textarea id="new-keyword-template" class="large-text" rows="3" placeholder="Enter your response template..."></textarea>
                </td>
              </tr>
            </table>
          </div>
          <div class="luna-modal-footer">
            <button type="button" id="save-new-keyword" class="button button-primary">Add Keyword</button>
            <button type="button" id="cancel-new-keyword" class="button">Cancel</button>
          </div>
        </div>
      </div>
      
      <!-- Modal for adding new category -->
      <div id="category-modal" class="luna-modal" style="display: none;">
        <div class="luna-modal-content">
          <div class="luna-modal-header">
            <h2>Add New Category</h2>
            <span class="luna-modal-close">&times;</span>
          </div>
          <div class="luna-modal-body">
            <table class="form-table">
              <tr>
                <th scope="row">Category Name</th>
                <td>
                  <input type="text" id="new-category-name" class="regular-text" placeholder="e.g., products, services, support">
                  <p class="description">Enter a name for the new category</p>
                </td>
              </tr>
              <tr>
                <th scope="row">Description</th>
                <td>
                  <input type="text" id="new-category-description" class="regular-text" placeholder="Brief description of this category">
                  <p class="description">Optional description for this category</p>
                </td>
              </tr>
            </table>
          </div>
          <div class="luna-modal-footer">
            <button type="button" id="save-new-category" class="button button-primary">Add Category</button>
            <button type="button" id="cancel-new-category" class="button">Cancel</button>
          </div>
        </div>
      </div>
      
      <!-- Modal for managing existing keywords -->
      <div id="manage-modal" class="luna-modal" style="display: none;">
        <div class="luna-modal-content" style="width: 80%; max-width: 800px;">
          <div class="luna-modal-header">
            <h2>Manage Existing Keywords</h2>
            <span class="luna-modal-close">&times;</span>
          </div>
          <div class="luna-modal-body">
            <p>Move existing keywords to different categories:</p>
            <div id="keyword-management-list"></div>
          </div>
          <div class="luna-modal-footer">
            <button type="button" id="save-keyword-changes" class="button button-primary">Save Changes</button>
            <button type="button" id="cancel-keyword-changes" class="button">Cancel</button>
          </div>
        </div>
      </div>
    
    <div class="luna-keywords-help">
      <h3>Template Variables</h3>
      <p>Use these variables in your response templates:</p>
      <ul>
        <li><code>{pages_list}</code> - List of pages with status</li>
        <li><code>{posts_list}</code> - List of posts with status</li>
        <li><code>{themes_list}</code> - List of themes with active status</li>
        <li><code>{plugins_list}</code> - List of plugins with active status</li>
        <li><code>{user_count}</code> - Number of users</li>
        <li><code>{user_plural}</code> - "s" if multiple users, "" if single</li>
        <li><code>{plugin_updates}</code> - Number of plugin updates available</li>
        <li><code>{theme_updates}</code> - Number of theme updates available</li>
        <li><code>{core_updates}</code> - Number of WordPress core updates available</li>
        <li><code>{ssl_status}</code> - SSL certificate status</li>
      </ul>
    </div>
    
    <form method="post">
      <?php wp_nonce_field('luna_keywords_nonce'); ?>
      
      <div class="luna-keywords-container">
        <?php foreach ($mappings as $category => $keywords): ?>
          <div class="luna-keyword-category">
            <h3><?php echo ucfirst($category); ?> Keywords</h3>
            <table class="form-table">
              <?php foreach ($keywords as $action => $config): ?>
                <?php 
                // Handle both old format (array of terms) and new format (config object)
                $terms = is_array($config) && isset($config['keywords']) ? $config['keywords'] : $config;
                $template = is_array($config) && isset($config['template']) ? $config['template'] : '';
                $data_source = is_array($config) && isset($config['data_source']) ? $config['data_source'] : 'custom';
                $enabled = is_array($config) && isset($config['enabled']) ? $config['enabled'] : 'off';
                
                // Debug: Show enabled state for this keyword (only in debug mode)
                if (WP_DEBUG) {
                  echo "<!-- DEBUG: {$category}.{$action} - enabled: {$enabled} -->";
                }
                ?>
                <tr>
                  <th scope="row"><?php echo ucfirst($action); ?></th>
                  <td>
                    <div class="luna-keyword-config">
                      <div class="luna-keyword-field">
                        <label>
                          <input type="checkbox" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][enabled]" 
                                 value="on" <?php checked('on', $enabled); ?> 
                                 onchange="luna_toggle_keyword('<?php echo $category; ?>', '<?php echo $action; ?>')">
                          Enable this keyword
                        </label>
                      </div>
                      
                      <div class="luna-keyword-field">
                        <label>Keywords:</label>
                        <input type="text" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][terms]" 
                               value="<?php echo esc_attr(is_array($terms) ? implode(', ', $terms) : $terms); ?>" 
                               class="regular-text" 
                               placeholder="Enter keywords separated by commas">
                      </div>
                      
                      <div class="luna-keyword-field">
                        <label>Data Source:</label>
                        <select name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][data_source]" 
                                onchange="luna_toggle_data_source_options(this, '<?php echo $category; ?>', '<?php echo $action; ?>')">
                          <option value="custom" <?php selected($data_source, 'custom'); ?>>Custom Response</option>
                          <option value="wp_rest" <?php selected($data_source, 'wp_rest'); ?>>WordPress Data</option>
                          <option value="security" <?php selected($data_source, 'security'); ?>>Security Data</option>
                        </select>
                      </div>
                      
                      <!-- WordPress Data Options -->
                      <div class="luna-data-source-options luna-wp-rest-options" 
                           style="display: <?php echo $data_source === 'wp_rest' ? 'block' : 'none'; ?>;">
                        <div class="luna-keyword-field">
                          <label>WordPress Data Response:</label>
                          <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][wp_template]" 
                                    class="large-text" rows="3" 
                                    placeholder="Use variables: {pages_list}, {posts_list}, {themes_list}, {plugins_list}, {user_count}, {user_plural}, {plugin_updates}, {theme_updates}, {core_updates}"><?php echo esc_textarea($config['wp_template'] ?? ''); ?></textarea>
                          <p class="description">
                            <strong>Available Variables:</strong><br>
                            <code>{pages_list}</code> - List of pages with status<br>
                            <code>{posts_list}</code> - List of posts with status<br>
                            <code>{themes_list}</code> - List of themes with active status<br>
                            <code>{plugins_list}</code> - List of plugins with active status<br>
                            <code>{user_count}</code> - Number of users<br>
                            <code>{user_plural}</code> - "s" if multiple users, "" if single<br>
                            <code>{plugin_updates}</code> - Number of plugin updates available<br>
                            <code>{theme_updates}</code> - Number of theme updates available<br>
                            <code>{core_updates}</code> - Number of WordPress core updates available
                          </p>
                        </div>
                        <div class="luna-keyword-field">
                          <label>Shortcode Generator:</label>
                          <select onchange="luna_insert_shortcode(this.value, 'keywords[<?php echo $category; ?>][<?php echo $action; ?>][wp_template]')">
                            <option value="">Select a shortcode to insert...</option>
                            <option value="{pages_list}">Pages List</option>
                            <option value="{posts_list}">Posts List</option>
                            <option value="{themes_list}">Themes List</option>
                            <option value="{plugins_list}">Plugins List</option>
                            <option value="{user_count}">User Count</option>
                            <option value="{plugin_updates}">Plugin Updates</option>
                            <option value="{theme_updates}">Theme Updates</option>
                            <option value="{core_updates}">Core Updates</option>
                          </select>
                        </div>
                      </div>
                      
                      <!-- Security Data Options -->
                      <div class="luna-data-source-options luna-security-options" 
                           style="display: <?php echo $data_source === 'security' ? 'block' : 'none'; ?>;">
                        <div class="luna-keyword-field">
                          <label>Security Data Response:</label>
                          <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][security_template]" 
                                    class="large-text" rows="3" 
                                    placeholder="Use variables: {ssl_status}, {firewall_status}, {backup_status}, {monitoring_status}"><?php echo esc_textarea($config['security_template'] ?? ''); ?></textarea>
                          <p class="description">
                            <strong>Available Variables:</strong><br>
                            <code>{ssl_status}</code> - SSL certificate status<br>
                            <code>{firewall_status}</code> - Firewall protection status<br>
                            <code>{backup_status}</code> - Backup information<br>
                            <code>{monitoring_status}</code> - Security monitoring details
                          </p>
                        </div>
                        <div class="luna-keyword-field">
                          <label>Shortcode Generator:</label>
                          <select onchange="luna_insert_shortcode(this.value, 'keywords[<?php echo $category; ?>][<?php echo $action; ?>][security_template]')">
                            <option value="">Select a shortcode to insert...</option>
                            <option value="{ssl_status}">SSL Status</option>
                            <option value="{firewall_status}">Firewall Status</option>
                            <option value="{backup_status}">Backup Status</option>
                            <option value="{monitoring_status}">Monitoring Status</option>
                          </select>
                        </div>
                      </div>
                      
                      <!-- Custom Response Options -->
                      <div class="luna-data-source-options luna-custom-options" 
                           style="display: <?php echo $data_source === 'custom' ? 'block' : 'none'; ?>;">
                        <div class="luna-response-type">
                          <label>
                            <input type="radio" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][response_type]" 
                                   value="simple" <?php checked($config['response_type'] ?? 'simple', 'simple'); ?> 
                                   onchange="luna_toggle_response_type('<?php echo $category; ?>', '<?php echo $action; ?>', 'simple')">
                            Simple Text Response
                          </label>
                          <label>
                            <input type="radio" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][response_type]" 
                                   value="advanced" <?php checked($config['response_type'] ?? 'simple', 'advanced'); ?> 
                                   onchange="luna_toggle_response_type('<?php echo $category; ?>', '<?php echo $action; ?>', 'advanced')">
                            Advanced Conversation Flows
                          </label>
                        </div>
                        
                        <!-- Simple Text Response -->
                        <div class="luna-simple-response" 
                             style="display: <?php echo ($config['response_type'] ?? 'simple') === 'simple' ? 'block' : 'none'; ?>;">
                          <div class="luna-keyword-field">
                            <label>Response Template:</label>
                            <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][template]" 
                                      class="large-text" rows="3" 
                                      placeholder="Enter your response template..."><?php echo esc_textarea($template); ?></textarea>
                            <p class="description">
                              <strong>Available Shortcodes:</strong><br>
                              <code>[contact_page]</code> - Link to contact page<br>
                              <code>[booking_link]</code> - Link to booking page<br>
                              <code>[phone_number]</code> - Phone number link<br>
                              <code>[email_link]</code> - Email link<br>
                              <code>[site_url]</code> - Site URL<br>
                              <code>[business_name]</code> - Business name
                            </p>
                          </div>
                          <div class="luna-keyword-field">
                            <label>Shortcode Generator:</label>
                            <select onchange="luna_insert_shortcode(this.value, 'keywords[<?php echo $category; ?>][<?php echo $action; ?>][template]')">
                              <option value="">Select a shortcode to insert...</option>
                              <option value="[contact_page]">Contact Page Link</option>
                              <option value="[booking_link]">Booking Link</option>
                              <option value="[phone_number]">Phone Number</option>
                              <option value="[email_link]">Email Link</option>
                              <option value="[site_url]">Site URL</option>
                              <option value="[business_name]">Business Name</option>
                            </select>
                          </div>
                        </div>
                        
                        <!-- Advanced Conversation Flows -->
                        <div class="luna-advanced-response" 
                             style="display: <?php echo ($config['response_type'] ?? 'simple') === 'advanced' ? 'block' : 'none'; ?>;">
                          <div class="luna-keyword-field">
                            <label>Initial Response:</label>
                            <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][initial_response]" 
                                      class="large-text" rows="2" 
                                      placeholder="What should Luna say first?"><?php echo esc_textarea($config['initial_response'] ?? ''); ?></textarea>
                          </div>
                          <div class="luna-keyword-field">
                            <label>Follow-up Responses:</label>
                            <div class="luna-branch-responses">
                              <div class="luna-branch-item">
                                <input type="text" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][branches][yes][trigger]" 
                                       placeholder="User says (e.g., 'yes', 'sure', 'okay')" 
                                       value="<?php echo esc_attr($config['branches']['yes']['trigger'] ?? 'yes'); ?>">
                                <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][branches][yes][response]" 
                                          placeholder="Luna responds..." 
                                          rows="2"><?php echo esc_textarea($config['branches']['yes']['response'] ?? ''); ?></textarea>
                              </div>
                              <div class="luna-branch-item">
                                <input type="text" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][branches][no][trigger]" 
                                       placeholder="User says (e.g., 'no', 'not now', 'maybe later')" 
                                       value="<?php echo esc_attr($config['branches']['no']['trigger'] ?? 'no'); ?>">
                                <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][branches][no][response]" 
                                          placeholder="Luna responds..." 
                                          rows="2"><?php echo esc_textarea($config['branches']['no']['response'] ?? ''); ?></textarea>
                              </div>
                              <div class="luna-branch-item">
                                <input type="text" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][branches][maybe][trigger]" 
                                       placeholder="User says (e.g., 'maybe', 'not sure', 'tell me more')" 
                                       value="<?php echo esc_attr($config['branches']['maybe']['trigger'] ?? 'maybe'); ?>">
                                <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][branches][maybe][response]" 
                                          placeholder="Luna responds..." 
                                          rows="2"><?php echo esc_textarea($config['branches']['maybe']['response'] ?? ''); ?></textarea>
                              </div>
                            </div>
                            <p class="description">Define how Luna should respond based on different user inputs.</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  </td>
                </tr>
              <?php endforeach; ?>
            </table>
          </div>
        <?php endforeach; ?>
      </div>
      
      <p class="submit">
        <input type="submit" name="save_keywords" class="button-primary" value="Save Keywords & Templates">
        <a href="#" class="button" onclick="luna_export_keywords(); return false;">Export Keywords</a>
        <a href="#" class="button" onclick="luna_import_keywords(); return false;">Import Keywords</a>
      </p>
    </form>
  </div>
  
  <style>
    .luna-keywords-container {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
      gap: 20px;
      margin: 20px 0;
    }
    .luna-keyword-category {
      border: 1px solid #ddd;
      padding: 15px;
      border-radius: 5px;
      background: #f9f9f9;
    }
    .luna-keyword-category h3 {
      margin-top: 0;
      color: #23282d;
    }
    .luna-keyword-config {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .luna-keyword-field {
      display: flex;
      flex-direction: column;
    }
    .luna-keyword-field label {
      font-weight: bold;
      margin-bottom: 5px;
    }
    .luna-keywords-help {
      background: #e7f3ff;
      border: 1px solid #0073aa;
      border-radius: 5px;
      padding: 15px;
      margin: 20px 0;
    }
    .luna-keywords-help h3 {
      margin-top: 0;
      color: #0073aa;
    }
    .luna-keywords-help code {
      background: #fff;
      padding: 2px 4px;
      border-radius: 3px;
      font-family: monospace;
    }
    
    /* Modal Styles */
    .luna-modal {
      position: fixed;
      z-index: 100000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    
    .luna-modal-content {
      background-color: #fff;
      border-radius: 4px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      width: 90%;
      max-width: 600px;
      max-height: 90vh;
      overflow-y: auto;
    }
    
    .luna-modal-header {
      padding: 20px;
      border-bottom: 1px solid #ddd;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #f1f1f1;
    }
    
    .luna-modal-header h2 {
      margin: 0;
      font-size: 18px;
    }
    
    .luna-modal-close {
      font-size: 24px;
      font-weight: bold;
      cursor: pointer;
      color: #666;
    }
    
    .luna-modal-close:hover {
      color: #000;
    }
    
    .luna-modal-body {
      padding: 20px;
    }
    
    .luna-modal-footer {
      padding: 20px;
      border-top: 1px solid #ddd;
      text-align: right;
      background: #f9f9f9;
    }
    
    .luna-modal-footer .button {
      margin-left: 10px;
    }
    
    .keyword-management-item {
      display: flex;
      align-items: center;
      padding: 10px;
      border: 1px solid #ddd;
      border-radius: 4px;
      margin-bottom: 10px;
      background: #fff;
    }
    
    .keyword-management-item select {
      margin-left: 10px;
      min-width: 150px;
    }
    
    .keyword-management-item .keyword-info {
      flex: 1;
    }
    
    .keyword-management-item .keyword-name {
      font-weight: 600;
    }
    
    .keyword-management-item .keyword-terms {
      color: #666;
      font-size: 12px;
    }
  </style>
  
  <script>
    function luna_export_keywords() {
      // TODO: Implement keyword export functionality
      alert('Export functionality coming soon!');
    }
    
    function luna_import_keywords() {
      // TODO: Implement keyword import functionality
      alert('Import functionality coming soon!');
    }
  </script>
  <?php
}

// Analytics admin page
function luna_widget_analytics_admin_page() {
  $performance = luna_get_keyword_performance();
  ?>
  <div class="wrap">
    <h1>Luna Chat Analytics</h1>
    <p>Track keyword performance and usage statistics to optimize your Luna Chat experience.</p>
    
    <?php if (empty($performance)): ?>
      <div class="notice notice-info">
        <p>No keyword usage data available yet. Start using Luna Chat to see analytics!</p>
      </div>
    <?php else: ?>
      <div class="luna-analytics-container">
        <div class="luna-analytics-summary">
          <h3>Summary</h3>
          <div class="luna-stats-grid">
            <div class="luna-stat-box">
              <h4>Total Keywords Used</h4>
              <span class="luna-stat-number"><?php echo count($performance); ?></span>
            </div>
            <div class="luna-stat-box">
              <h4>Total Interactions</h4>
              <span class="luna-stat-number"><?php echo array_sum(array_column($performance, 'total_uses')); ?></span>
            </div>
            <div class="luna-stat-box">
              <h4>Average Success Rate</h4>
              <span class="luna-stat-number"><?php 
                $avg_success = array_sum(array_column($performance, 'success_rate')) / count($performance);
                echo round($avg_success, 1) . '%';
              ?></span>
            </div>
          </div>
        </div>
        
        <div class="luna-analytics-details">
          <h3>Keyword Performance</h3>
          <table class="wp-list-table widefat fixed striped">
            <thead>
              <tr>
                <th>Keyword</th>
                <th>Category</th>
                <th>Total Uses</th>
                <th>Success Rate</th>
                <th>Last Used</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($performance as $key => $stats): ?>
                <?php 
                list($category, $action) = explode('.', $key, 2);
                $success_class = $stats['success_rate'] >= 80 ? 'success' : ($stats['success_rate'] >= 60 ? 'warning' : 'error');
                ?>
                <tr>
                  <td><strong><?php echo esc_html(ucfirst($action)); ?></strong></td>
                  <td><?php echo esc_html(ucfirst($category)); ?></td>
                  <td><?php echo $stats['total_uses']; ?></td>
                  <td>
                    <span class="luna-success-rate luna-<?php echo $success_class; ?>">
                      <?php echo $stats['success_rate']; ?>%
                    </span>
                  </td>
                  <td><?php echo esc_html($stats['last_used']); ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
        
        <div class="luna-analytics-insights">
          <h3>Insights & Recommendations</h3>
          <div class="luna-insights">
            <?php
            $low_performing = array_filter($performance, function($stats) {
              return $stats['success_rate'] < 60 && $stats['total_uses'] > 2;
            });
            
            $unused = array_filter($performance, function($stats) {
              return $stats['total_uses'] == 0;
            });
            
            $high_performing = array_filter($performance, function($stats) {
              return $stats['success_rate'] >= 90 && $stats['total_uses'] > 5;
            });
            ?>
            
            <?php if (!empty($low_performing)): ?>
              <div class="luna-insight warning">
                <h4>⚠️ Low Performing Keywords</h4>
                <p>These keywords have low success rates and may need attention:</p>
                <ul>
                  <?php foreach ($low_performing as $key => $stats): ?>
                    <li><strong><?php echo esc_html(ucfirst(explode('.', $key)[1])); ?></strong> - <?php echo $stats['success_rate']; ?>% success rate</li>
                  <?php endforeach; ?>
                </ul>
                <p><em>Consider reviewing the response templates or adding more specific keywords.</em></p>
              </div>
            <?php endif; ?>
            
            <?php if (!empty($high_performing)): ?>
              <div class="luna-insight success">
                <h4>✅ High Performing Keywords</h4>
                <p>These keywords are working well:</p>
                <ul>
                  <?php foreach ($high_performing as $key => $stats): ?>
                    <li><strong><?php echo esc_html(ucfirst(explode('.', $key)[1])); ?></strong> - <?php echo $stats['success_rate']; ?>% success rate</li>
                  <?php endforeach; ?>
                </ul>
                <p><em>Great job! These responses are working effectively.</em></p>
              </div>
            <?php endif; ?>
            
            <?php if (empty($low_performing) && empty($high_performing)): ?>
              <div class="luna-insight info">
                <h4>📊 Keep Using Luna Chat</h4>
                <p>Continue using Luna Chat to build up more performance data. The more interactions you have, the better insights we can provide!</p>
              </div>
            <?php endif; ?>
          </div>
        </div>
      </div>
    <?php endif; ?>
  </div>
  
  <style>
    .luna-analytics-container {
      display: flex;
      flex-direction: column;
      gap: 30px;
    }
    .luna-stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin: 20px 0;
    }
    .luna-stat-box {
      background: #f8f9fa;
      border: 1px solid #dee2e6;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }
    .luna-stat-box h4 {
      margin: 0 0 10px 0;
      color: #6c757d;
      font-size: 14px;
      font-weight: 600;
    }
    .luna-stat-number {
      font-size: 32px;
      font-weight: bold;
      color: #0073aa;
    }
    .luna-success-rate {
      padding: 4px 8px;
      border-radius: 4px;
      font-weight: bold;
    }
    .luna-success-rate.luna-success {
      background: #d4edda;
      color: #155724;
    }
    .luna-success-rate.luna-warning {
      background: #fff3cd;
      color: #856404;
    }
    .luna-success-rate.luna-error {
      background: #f8d7da;
      color: #721c24;
    }
    .luna-insights {
      display: flex;
      flex-direction: column;
      gap: 20px;
    }
    .luna-insight {
      padding: 20px;
      border-radius: 8px;
      border-left: 4px solid;
    }
    .luna-insight.success {
      background: #d4edda;
      border-left-color: #28a745;
    }
    .luna-insight.warning {
      background: #fff3cd;
      border-left-color: #ffc107;
    }
    .luna-insight.info {
      background: #d1ecf1;
      border-left-color: #17a2b8;
    }
    .luna-insight h4 {
      margin-top: 0;
    }
    .luna-insight ul {
      margin: 10px 0;
    }
    
    /* Keyword Interface Styles */
    .luna-data-source-options {
      margin-top: 15px;
      padding: 15px;
      background: #f8f9fa;
      border: 1px solid #dee2e6;
      border-radius: 6px;
    }
    
    .luna-response-type {
      margin-bottom: 15px;
    }
    
    .luna-response-type label {
      display: inline-block;
      margin-right: 20px;
      font-weight: 600;
    }
    
    .luna-response-type input[type="radio"] {
      margin-right: 8px;
    }
    
    .luna-branch-responses {
      display: flex;
      flex-direction: column;
      gap: 15px;
    }
    
    .luna-branch-item {
      display: flex;
      flex-direction: column;
      gap: 8px;
      padding: 12px;
      background: #ffffff;
      border: 1px solid #e9ecef;
      border-radius: 4px;
    }
    
    .luna-branch-item input[type="text"] {
      padding: 8px 12px;
      border: 1px solid #ced4da;
      border-radius: 4px;
      font-size: 14px;
    }
    
    .luna-branch-item textarea {
      padding: 8px 12px;
      border: 1px solid #ced4da;
      border-radius: 4px;
      font-size: 14px;
      resize: vertical;
    }
    
    .luna-keyword-field .description {
      margin-top: 8px;
      font-size: 13px;
      color: #6c757d;
      line-height: 1.4;
    }
    
    .luna-keyword-field .description code {
      background: #e9ecef;
      padding: 2px 4px;
      border-radius: 3px;
      font-family: 'Courier New', monospace;
      font-size: 12px;
    }
    
    .luna-keyword-field select {
      padding: 6px 10px;
      border: 1px solid #ced4da;
      border-radius: 4px;
      font-size: 14px;
    }
  </style>
  <?php
}

// Separate function for JavaScript
function luna_keywords_admin_scripts() {
  ?>
  <script>
  function luna_toggle_keyword(category, action) {
    const checkbox = document.querySelector(`input[name="keywords[${category}][${action}][enabled]"]`);
    const row = checkbox.closest('tr');
    const inputs = row.querySelectorAll('input, textarea, select');
    
    inputs.forEach(input => {
      if (input !== checkbox) {
        input.disabled = !checkbox.checked;
      }
    });
  }
  
  function luna_toggle_data_source_options(select, category, action) {
    const dataSource = select.value;
    const row = select.closest('tr');
    
    console.log('Luna Keywords: Toggling data source to', dataSource, 'for', category, action);
    
    // Hide all data source options
    row.querySelectorAll('.luna-data-source-options').forEach(div => {
      div.style.display = 'none';
    });
    
    // Show the selected data source options
    const targetDiv = row.querySelector(`.luna-${dataSource}-options`);
    if (targetDiv) {
      targetDiv.style.display = 'block';
      console.log('Luna Keywords: Showing', dataSource, 'options');
      
      // If it's custom response, also initialize the response type
      if (dataSource === 'custom') {
        const checkedRadio = targetDiv.querySelector('input[name*="[response_type]"]:checked');
        if (checkedRadio) {
          console.log('Luna Keywords: Found checked radio, initializing response type');
          luna_toggle_response_type(category, action, checkedRadio.value);
        }
      }
    } else {
      console.log('Luna Keywords: Target div not found for', dataSource);
    }
  }
  
  function luna_toggle_response_type(category, action, type) {
    const radio = document.querySelector(`input[name="keywords[${category}][${action}][response_type]"][value="${type}"]`);
    if (!radio) {
      console.log('Luna Keywords: Radio not found for', category, action, type);
      return;
    }
    
    const row = radio.closest('tr');
    
    console.log('Luna Keywords: Toggling response type to', type, 'for', category, action);
    
    // Hide both response types
    row.querySelectorAll('.luna-simple-response, .luna-advanced-response').forEach(div => {
      div.style.display = 'none';
    });
    
    // Show the selected response type
    const targetDiv = row.querySelector(`.luna-${type}-response`);
    if (targetDiv) {
      targetDiv.style.display = 'block';
      console.log('Luna Keywords: Showing', type, 'response');
    } else {
      console.log('Luna Keywords: Target div not found for', type, 'response');
    }
  }
  
  function luna_insert_shortcode(shortcode, targetFieldName) {
    if (!shortcode) return;
    
    const textarea = document.querySelector(`textarea[name="${targetFieldName}"]`);
    if (textarea) {
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      const text = textarea.value;
      const before = text.substring(0, start);
      const after = text.substring(end, text.length);
      
      textarea.value = before + shortcode + after;
      textarea.focus();
      textarea.setSelectionRange(start + shortcode.length, start + shortcode.length);
    }
  }
  
  // Modal functionality
  function openModal(modalId) {
    document.getElementById(modalId).style.display = 'flex';
  }
  
  function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
  }
  
  // Add new keyword functionality
  function addNewKeyword() {
    openModal('keyword-modal');
  }
  
  function saveNewKeyword() {
    const category = document.getElementById('new-keyword-category').value;
    const action = document.getElementById('new-keyword-name').value;
    const terms = document.getElementById('new-keyword-terms').value;
    const dataSource = document.getElementById('new-keyword-data-source').value;
    const template = document.getElementById('new-keyword-template').value;
    
    if (!action || !terms) {
      alert('Please fill in the keyword name and terms.');
      return;
    }
    
    // Create new keyword row
    const container = document.querySelector('.luna-keywords-container');
    const newRow = document.createElement('div');
    newRow.className = 'luna-keyword-category';
    newRow.innerHTML = `
      <h3>${category.charAt(0).toUpperCase() + category.slice(1)} Keywords</h3>
      <table class="form-table">
        <tr>
          <th scope="row">${action.charAt(0).toUpperCase() + action.slice(1)}</th>
          <td>
            <div class="luna-keyword-config">
              <div class="luna-keyword-field">
                <label>
                  <input type="checkbox" name="keywords[${category}][${action}][enabled]" value="on" checked onchange="luna_toggle_keyword('${category}', '${action}')">
                  Enable this keyword
                </label>
              </div>
              <div class="luna-keyword-field">
                <label>Keywords:</label>
                <input type="text" name="keywords[${category}][${action}][terms]" class="regular-text" value="${terms}">
              </div>
              <div class="luna-keyword-field">
                <label>Data Source:</label>
                <select name="keywords[${category}][${action}][data_source]" onchange="luna_toggle_data_source_options(this, '${category}', '${action}')">
                  <option value="custom" ${dataSource === 'custom' ? 'selected' : ''}>Custom Response</option>
                  <option value="wp_rest" ${dataSource === 'wp_rest' ? 'selected' : ''}>WordPress Data</option>
                  <option value="security" ${dataSource === 'security' ? 'selected' : ''}>Security Data</option>
                </select>
              </div>
              <div class="luna-keyword-field">
                <label>Response Template:</label>
                <textarea name="keywords[${category}][${action}][template]" class="large-text" rows="3">${template}</textarea>
              </div>
            </div>
          </td>
        </tr>
      </table>
    `;
    
    // Add to container
    container.appendChild(newRow);
    
    // Initialize the new keyword
    luna_toggle_keyword(category, action);
    
    // Clear form and close modal
    document.getElementById('new-keyword-name').value = '';
    document.getElementById('new-keyword-terms').value = '';
    document.getElementById('new-keyword-template').value = '';
    closeModal('keyword-modal');
  }
  
  // Add new category functionality
  function addNewCategory() {
    openModal('category-modal');
  }
  
  function saveNewCategory() {
    const categoryName = document.getElementById('new-category-name').value;
    const description = document.getElementById('new-category-description').value;
    
    if (!categoryName) {
      alert('Please enter a category name.');
      return;
    }
    
    // Add to category dropdown
    const categorySelect = document.getElementById('new-keyword-category');
    const newOption = document.createElement('option');
    newOption.value = categoryName.toLowerCase().replace(/\s+/g, '_');
    newOption.textContent = categoryName.charAt(0).toUpperCase() + categoryName.slice(1);
    categorySelect.appendChild(newOption);
    
    // Clear form and close modal
    document.getElementById('new-category-name').value = '';
    document.getElementById('new-category-description').value = '';
    closeModal('category-modal');
    
    alert(`Category "${categoryName}" added successfully! You can now use it when adding new keywords.`);
  }
  
  // Manage existing keywords functionality
  function manageKeywords() {
    const container = document.getElementById('keyword-management-list');
    container.innerHTML = '';
    
    // Get all existing keywords
    const keywords = [];
    document.querySelectorAll('.luna-keyword-category').forEach(categoryDiv => {
      const categoryName = categoryDiv.querySelector('h3').textContent.replace(' Keywords', '').toLowerCase();
      categoryDiv.querySelectorAll('tr').forEach(row => {
        const th = row.querySelector('th');
        if (th && th.textContent.trim()) {
          const actionName = th.textContent.trim();
          const termsInput = row.querySelector('input[name*="[terms]"]');
          const terms = termsInput ? termsInput.value : '';
          
          keywords.push({
            category: categoryName,
            action: actionName,
            terms: terms,
            element: row
          });
        }
      });
    });
    
    // Create management interface
    keywords.forEach(keyword => {
      const item = document.createElement('div');
      item.className = 'keyword-management-item';
      item.innerHTML = `
        <div class="keyword-info">
          <div class="keyword-name">${keyword.action}</div>
          <div class="keyword-terms">${keyword.terms}</div>
        </div>
        <select data-category="${keyword.category}" data-action="${keyword.action}">
          <option value="business" ${keyword.category === 'business' ? 'selected' : ''}>Business</option>
          <option value="wp_rest" ${keyword.category === 'wp_rest' ? 'selected' : ''}>WordPress Data</option>
          <option value="security" ${keyword.category === 'security' ? 'selected' : ''}>Security</option>
          <option value="custom" ${keyword.category === 'custom' ? 'selected' : ''}>Custom</option>
        </select>
      `;
      container.appendChild(item);
    });
    
    openModal('manage-modal');
  }
  
  function saveKeywordChanges() {
    const changes = [];
    document.querySelectorAll('#keyword-management-list select').forEach(select => {
      const category = select.dataset.category;
      const action = select.dataset.action;
      const newCategory = select.value;
      
      if (category !== newCategory) {
        changes.push({ category, action, newCategory });
      }
    });
    
    if (changes.length === 0) {
      closeModal('manage-modal');
      return;
    }
    
    // Apply changes
    changes.forEach(change => {
      // Find the row and move it to the new category
      const row = document.querySelector(`input[name*="[${change.action}][enabled]"]`).closest('tr');
      const categoryDiv = row.closest('.luna-keyword-category');
      
      // Update the category name in the row
      const categorySelect = row.querySelector('select[name*="[data_source]"]');
      if (categorySelect) {
        const name = categorySelect.name;
        const newName = name.replace(`[${change.category}]`, `[${change.newCategory}]`);
        categorySelect.name = newName;
      }
      
      // Update all form elements in the row
      row.querySelectorAll('input, select, textarea').forEach(input => {
        if (input.name && input.name.includes(`[${change.category}]`)) {
          input.name = input.name.replace(`[${change.category}]`, `[${change.newCategory}]`);
        }
      });
    });
    
    closeModal('manage-modal');
    alert(`Moved ${changes.length} keyword(s) to new categories. Don't forget to save the form!`);
  }
  
  // Initialize the interface on page load
  document.addEventListener('DOMContentLoaded', function() {
    console.log('Luna Keywords: Initializing interface...');
    
    // Button event listeners
    document.getElementById('add-new-keyword').addEventListener('click', addNewKeyword);
    document.getElementById('add-new-category').addEventListener('click', addNewCategory);
    document.getElementById('manage-keywords').addEventListener('click', manageKeywords);
    
    // Modal event listeners
    document.getElementById('save-new-keyword').addEventListener('click', saveNewKeyword);
    document.getElementById('cancel-new-keyword').addEventListener('click', () => closeModal('keyword-modal'));
    document.getElementById('save-new-category').addEventListener('click', saveNewCategory);
    document.getElementById('cancel-new-category').addEventListener('click', () => closeModal('category-modal'));
    document.getElementById('save-keyword-changes').addEventListener('click', saveKeywordChanges);
    document.getElementById('cancel-keyword-changes').addEventListener('click', () => closeModal('manage-modal'));
    
    // Close modal when clicking X
    document.querySelectorAll('.luna-modal-close').forEach(closeBtn => {
      closeBtn.addEventListener('click', function() {
        const modal = this.closest('.luna-modal');
        modal.style.display = 'none';
      });
    });
    
    // Close modal when clicking outside
    document.querySelectorAll('.luna-modal').forEach(modal => {
      modal.addEventListener('click', function(e) {
        if (e.target === this) {
          this.style.display = 'none';
        }
      });
    });
    
    // Initialize all data source options
    document.querySelectorAll('select[name*="[data_source]"]').forEach(select => {
      const categoryMatch = select.name.match(/keywords\[([^\]]+)\]/);
      const actionMatch = select.name.match(/\[([^\]]+)\]\[data_source\]/);
      
      if (categoryMatch && actionMatch) {
        const category = categoryMatch[1];
        const action = actionMatch[1];
        console.log('Luna Keywords: Initializing data source for', category, action, '=', select.value);
        luna_toggle_data_source_options(select, category, action);
      }
    });
    
    // Initialize all response types for custom responses
    document.querySelectorAll('input[name*="[response_type]"]:checked').forEach(radio => {
      const categoryMatch = radio.name.match(/keywords\[([^\]]+)\]/);
      const actionMatch = radio.name.match(/\[([^\]]+)\]\[response_type\]/);
      
      if (categoryMatch && actionMatch) {
        const category = categoryMatch[1];
        const action = actionMatch[1];
        const type = radio.value;
        console.log('Luna Keywords: Initializing response type for', category, action, '=', type);
        luna_toggle_response_type(category, action, type);
      }
    });
  });
  </script>
  <?php
}

/* ============================================================
 * SECURITY HELPERS
 * ============================================================ */
function luna_license_ok( WP_REST_Request $req ) {
  $saved = (string) get_option(LUNA_WIDGET_OPT_LICENSE, '');
  if ($saved === '') return false;
  $hdr = trim((string) ($req->get_header('X-Luna-License') ? $req->get_header('X-Luna-License') : ''));
  $qp  = trim((string) $req->get_param('license'));
  $provided = $hdr ? $hdr : $qp;
  if (!$provided) return false;
  if (!is_ssl() && $qp) return false; // only allow license in query over https
  return hash_equals($saved, $provided);
}
function luna_forbidden() {
  return new WP_REST_Response(array('ok'=>false,'error'=>'forbidden'), 403);
}
