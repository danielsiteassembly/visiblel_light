<?php
/**
 * Plugin Name: Luna License Manager
 * Description: Issue "Enterprise License Codes", receive heartbeats from client sites running the Luna Chat Widget, show Active/Inactive status, and render Client Profiles (Overview, Posts, Pages, Plugins, Themes, Users, Security, AI Chats, Cloud Connections).
 * Version:     1.3.1
 * Author:      Visible Light
 */

if (!defined('ABSPATH')) exit;

/* =======================================================================
 * Constants / Options
 * ===================================================================== */
define('VL_LIC_OPT_STORE',        'vl_licenses_registry');   // licenses registry (array)
define('VL_CONN_OPT_STORE',       'vl_client_connections');  // per-license cloud connections (array)
define('VL_PROFILE_CACHE_TTL',    300);                      // seconds for remote fetch cache
define('VL_PROFILE_CACHE_OPTION', 'vl_client_profile_cache');// option to stash fetched data
const  VL_LUNA_HASH_SALT = 'vl_luna_salt_v1';                // license hashing salt

/* =======================================================================
 * CPT: License placeholder (if you ever want to pivot to CPT storage)
 * ===================================================================== */
add_action('init', function () {
  register_post_type('luna_license', [
    'label'        => 'Luna Licenses',
    'public'       => false,
    'show_ui'      => false,
    'supports'     => ['title'],
    'map_meta_cap' => true,
  ]);
});

/* =======================================================================
 * Admin Menu (unified under “VL Clients”)
 * ===================================================================== */
if (!function_exists('vl_licenses_screen_bridge')) {
  function vl_licenses_screen_bridge(){
    if (function_exists('vl_licenses_screen')) return vl_licenses_screen();
    echo '<div class="wrap"><h1>Luna Licenses</h1><p>Renderer missing.</p></div>';
  }
}

/* =======================================================================
 * REST API: Client Data for Supercluster
 * ===================================================================== */

// Add API endpoint for clients
add_action('rest_api_init', function () {
    register_rest_route('vl-hub/v1', '/clients', array(
        'methods' => 'GET',
        'callback' => 'vl_get_clients_for_supercluster',
        'permission_callback' => 'vl_check_client_permissions_supercluster'
    ));
});

add_action('rest_api_init', function () {
    register_rest_route('vl-hub/v1', '/session', array(
        'methods'  => 'GET',
        'permission_callback' => '__return_true',
        'callback' => 'vl_hub_rest_session_info',
    ));
});

// Get clients from database for Supercluster visualization
function vl_get_clients_for_supercluster($request) {
    global $wpdb;
    
    // Try to get clients from your existing license system
    $licenses = get_option('vl_licenses_registry', array());
    
    $clients = array();
    
    if (!empty($licenses) && is_array($licenses)) {
        foreach ($licenses as $license_key => $license_data) {
            if (isset($license_data['client_name']) && isset($license_data['status']) && $license_data['status'] === 'active') {
                $clients[] = array(
                    'client_name' => $license_data['client_name'],
                    'license_key' => $license_key,
                    'status' => $license_data['status']
                );
            }
        }
    }
    
    // If no clients found in registry, use fallback
    if (empty($clients)) {
        $clients = array(
            array(
                'client_name' => 'Commonwealth Health Services',
                'license_key' => 'VL-VYAK-9BPQ-NKCC',
                'status' => 'active'
            ),
            array(
                'client_name' => 'Site Assembly',
                'license_key' => 'VL-H2K3-ZFQK-DKDC',
                'status' => 'active'
            ),
            array(
                'client_name' => 'Visible Light',
                'license_key' => 'VL-AWJJ-8J6S-GD6R',
                'status' => 'active'
            )
        );
    }
    
    return array(
        'success' => true,
        'clients' => $clients,
        'count' => count($clients),
        'source' => !empty($licenses) ? 'database' : 'fallback'
    );
}

// Check permissions for Supercluster API
function vl_check_client_permissions_supercluster($request) {
    // Check if user is logged in
    if (!is_user_logged_in()) {
        return new WP_Error('unauthorized', 'You must be logged in to access client data.', array('status' => 401));
    }

    // Check if user has permission to view clients
    if (!current_user_can('read')) {
        return new WP_Error('forbidden', 'You do not have permission to view client data.', array('status' => 403));
    }

    return true;
}

function vl_hub_rest_session_info(WP_REST_Request $request): WP_REST_Response {
  $default_dashboard = vl_lic_dashboard_url(null);
  $login_url         = wp_login_url($default_dashboard);

  if (!is_user_logged_in()) {
    return new WP_REST_Response([
      'authenticated' => false,
      'dashboard_url' => $default_dashboard,
      'login_url'     => $login_url,
      'permissions'   => [
        'can_view_clients'   => false,
        'can_manage_clients' => false,
      ],
    ], 200);
  }

  $user        = wp_get_current_user();
  $license_key = trim((string) get_user_meta($user->ID, 'vl_license_key', true));
  $client_name = trim((string) get_user_meta($user->ID, 'vl_client_name', true));
  $license     = $license_key ? vl_lic_lookup_by_key($license_key) : null;

  if (!$client_name) {
    if ($license && !empty($license['client'])) {
      $client_name = (string) $license['client'];
    } else {
      $client_name = $user->display_name ?: $user->user_login;
    }
  }

  $dashboard_url = $license_key ? vl_lic_dashboard_url($license, $license_key) : $default_dashboard;

  $response = [
    'authenticated' => true,
    'dashboard_url' => $dashboard_url,
    'login_url'     => $login_url,
    'user' => [
      'id'           => $user->ID,
      'display_name' => $user->display_name,
      'email'        => $user->user_email,
      'roles'        => array_values((array) $user->roles),
    ],
    'license' => null,
    'permissions' => [
      'can_view_clients'   => current_user_can('read'),
      'can_manage_clients' => current_user_can('list_users') || current_user_can('manage_options'),
    ],
  ];

  if ($license_key || $license) {
    $key_value = $license_key ?: ($license['key'] ?? '');
    $response['license'] = [
      'key'            => $key_value,
      'client_name'    => $client_name,
      'active'         => (bool) ($license['active'] ?? false),
      'site'           => $license['site'] ?? '',
      'id'             => $license['id'] ?? ($license['_store_id'] ?? null),
      'found'          => (bool) $license,
      'slug'           => vl_lic_dashboard_segment($key_value),
      'dashboard_url'  => $dashboard_url,
    ];
  }

  return new WP_REST_Response($response, 200);
}

add_action('admin_menu', function () {
  // Ensure unified parent exists (if Demo Console is inactive)
  if (empty($GLOBALS['admin_page_hooks']['vl-clients'])) {
    add_menu_page(
      'VL Clients',
      'VL Clients',
      'manage_options',
      'vl-clients',
      function () { echo '<div class="wrap"><h1>VL Clients</h1><p>Select an item from the submenu.</p></div>'; },
      'dashicons-admin-site-alt3',
      58
    );
  }

  add_submenu_page(
    'vl-clients',
    'Luna Licenses',
    'Luna Licenses',
    'manage_options',
    'vl-licenses',
    'vl_licenses_screen_bridge'
  );

  add_submenu_page(
    'vl-clients',
    'AI Constellation',
    'AI Constellation',
    'manage_options',
    'vl-constellation',
    'vl_render_constellation_dashboard'
  );

  // Client Profile viewer (hidden entry point via links)
  add_submenu_page(
    null,
    'Client Profile',
    'Client Profile',
    'manage_options',
    'vl-client-profile',
    'vl_render_client_profile'
  );
}, 20);

function vl_render_constellation_dashboard(): void {
  if (!current_user_can('manage_options')) {
    wp_die('Forbidden');
  }

  $html_url  = plugins_url('assets/constellation/supercluster-visualization.html', __FILE__);
  $rest_url  = rest_url('vl-hub/v1/constellation');
  $icons_url = plugins_url('assets/icons', __FILE__);
  $nonce     = wp_create_nonce('wp_rest');

  $iframe_src = add_query_arg([
    'rest'  => $rest_url,
    'nonce' => $nonce,
    'icons' => $icons_url,
  ], $html_url);

  echo '<div class="wrap vl-constellation-wrap">';
  echo '<h1>Visible Light AI Constellation</h1>';
  echo '<p class="description">Visualize how every Luna-powered client is performing across licensing, security, content, and AI engagement. Telemetry is sourced from the Luna widget, Visible Light Hub connectors, and Hub session logs.</p>';
  echo '<div class="vl-constellation-frame">';
  echo '<iframe src="' . esc_url($iframe_src) . '" style="width:100%;height:75vh;border:1px solid rgba(88,166,255,0.35);border-radius:18px;overflow:hidden;background:#02030b" allowfullscreen loading="lazy"></iframe>';
  echo '</div>';
  echo '</div>';
}

/* =======================================================================
 * Utilities: Licenses store, connections store, helpers
 * ===================================================================== */
function vl_lic_store_get(): array {
  $list = get_option(VL_LIC_OPT_STORE, []);
  return is_array($list) ? $list : [];
}
function vl_lic_store_set(array $list): void {
  update_option(VL_LIC_OPT_STORE, $list, false);
}

function vl_conn_store_get(): array {
  $list = get_option(VL_CONN_OPT_STORE, []);
  return is_array($list) ? $list : [];
}
function vl_conn_store_set(array $list): void {
  update_option(VL_CONN_OPT_STORE, $list, false);
}

function vl_lic_generate_key(): string {
  $alph = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  $chunk = function() use($alph){ $s=''; for($i=0;$i<4;$i++) $s .= $alph[random_int(0, strlen($alph)-1)]; return $s; };
  return 'VL-' . $chunk() . '-' . $chunk() . '-' . $chunk();
}
function vl_lic_create(string $client, string $site): array {
  $store = vl_lic_store_get();
  $id    = 'lic_' . wp_generate_uuid4();
  $key   = vl_lic_generate_key();
  $now   = time();
  $store[$id] = [
    'id'         => $id,
    'client'     => $client ?: 'Untitled Client',
    'site'       => $site,
    'key'        => $key,       // plain (UI shows redacted)
    'active'     => true,
    'created'    => $now,
    'last_seen'  => 0,
    'notes'      => '',
    // optional enrich fields updated by /activate or /heartbeat from client
    'site_name'  => '',
    'wp_version' => '',
    'plugin_version' => '',
  ];
  vl_lic_store_set($store);
  return $store[$id];
}
function vl_lic_create_with_key(string $client, string $site, string $key, bool $active = true): array {
  $store = vl_lic_store_get();
  $id    = 'lic_' . wp_generate_uuid4();
  $now   = time();
  $store[$id] = [
    'id'         => $id,
    'client'     => $client ?: 'Untitled Client',
    'site'       => $site,
    'key'        => $key,
    'active'     => $active,
    'created'    => $now,
    'last_seen'  => 0,
    'notes'      => 'Registered existing key',
    'site_name'  => '',
    'wp_version' => '',
    'plugin_version' => '',
  ];
  vl_lic_store_set($store);
  return $store[$id];
}
function vl_lic_redact(string $k): string {
  if (strlen($k) <= 6) return str_repeat('•', max(4, strlen($k)));
  return substr($k, 0, 6) . '…' . substr($k, -4);
}

function vl_lic_lookup_by_key(string $key): ?array {
  $key = trim($key);
  if ($key === '') {
    return null;
  }

  $store = vl_lic_store_get();
  foreach ($store as $id => $row) {
    if (!empty($row['key']) && hash_equals($row['key'], $key)) {
      if (!isset($row['id'])) {
        $row['id'] = $id;
      }
      $row['_store_id'] = $id;
      return $row;
    }
  }

  return null;
}

function vl_lic_dashboard_segment(string $license_key): string {
  $segment = preg_replace('/[^A-Za-z0-9\-]/', '-', $license_key);
  $segment = trim($segment, '-');
  if ($segment === '') {
    $segment = 'dashboard';
  }
  return strtolower($segment);
}

function vl_lic_dashboard_url(?array $license, string $license_key = ''): string {
  $key = $license['key'] ?? $license_key;
  if (!$key) {
    return home_url('/ai-constellation-console/');
  }

  $segment = vl_lic_dashboard_segment($key);
  $path    = trailingslashit('ai-constellation-console/' . $segment);
  return home_url('/' . $path);
}
function vl_status_pill_from_row(array $row): string {
  $now   = time();
  $seen  = (int)($row['last_seen'] ?? 0);
  $alive = $seen && ($now - $seen) <= 24*3600;
  $enabled = !empty($row['active']);
  if (!$enabled) {
    return '<span style="padding:2px 8px;border-radius:999px;background:#666;color:#fff;border:1px solid #444;font-weight:600;">Disabled</span>';
  }
  if ($alive) {
    return '<span style="padding:2px 8px;border-radius:999px;background:#e6ffed;color:#057a25;border:1px solid #b7f5c6;font-weight:600;">Active</span>';
  }
  return '<span style="padding:2px 8px;border-radius:999px;background:#ffecec;color:#a50000;border:1px solid #ffcccc;font-weight:600;">Inactive</span>';
}

/* =======================================================================
 * Admin POST: generate / toggle / register-existing
 * ===================================================================== */
add_action('admin_post_vl_lic_generate', function () {
  if (!current_user_can('manage_options')) wp_die('Forbidden');
  check_admin_referer('vl_lic_generate');
  $client = sanitize_text_field($_POST['client'] ?? '');
  $site   = esc_url_raw(trim((string)($_POST['site'] ?? '')));
  $row    = vl_lic_create($client, $site);
  set_transient('vl_lic_last_created', $row, 60);
  wp_redirect(add_query_arg(['page'=>'vl-licenses','created'=>'1'], admin_url('admin.php')));
  exit;
});
add_action('admin_post_vl_lic_toggle', function () {
  if (!current_user_can('manage_options')) wp_die('Forbidden');
  check_admin_referer('vl_lic_toggle');
  $id    = sanitize_text_field($_POST['id'] ?? '');
  $store = vl_lic_store_get();
  if (!empty($store[$id])) {
    $store[$id]['active'] = !empty($_POST['make_active']) ? true : false;
    vl_lic_store_set($store);
  }
  wp_redirect(add_query_arg(['page'=>'vl-licenses'], admin_url('admin.php')));
  exit;
});
add_action('admin_post_vl_lic_register_existing', function () {
  if (!current_user_can('manage_options')) wp_die('Forbidden');
  check_admin_referer('vl_lic_register_existing');
  $client = sanitize_text_field($_POST['client'] ?? '');
  $site   = esc_url_raw(trim((string)($_POST['site'] ?? '')));
  $key    = preg_replace('/[^A-Za-z0-9\-]/', '', (string)($_POST['key'] ?? ''));
  if ($key === '') {
    wp_redirect(add_query_arg(['page'=>'vl-licenses','err'=>'missing_key'], admin_url('admin.php'))); exit;
  }
  $store = vl_lic_store_get();
  foreach ($store as $id => $row) {
    if (!empty($row['key']) && hash_equals($row['key'], $key)) {
      $store[$id]['client'] = $client ?: ($row['client'] ?? 'Client');
      if ($site) $store[$id]['site'] = $site;
      $store[$id]['active'] = true;
      vl_lic_store_set($store);
      wp_redirect(add_query_arg(['page'=>'vl-licenses','updated'=>'1'], admin_url('admin.php'))); exit;
    }
  }
  $row = vl_lic_create_with_key($client, $site, $key, true);
  set_transient('vl_lic_last_created', $row, 60);
  wp_redirect(add_query_arg(['page'=>'vl-licenses','created'=>'1'], admin_url('admin.php')));
  exit;
});

add_action('admin_post_vl_lic_delete', function () {
  if (!current_user_can('manage_options')) wp_die('Forbidden');
  check_admin_referer('vl_lic_delete');
  $id = sanitize_text_field($_POST['id'] ?? '');
  if (!$id) {
    wp_redirect(add_query_arg(['page'=>'vl-licenses','err'=>'missing_id'], admin_url('admin.php'))); exit;
  }
  
  $store = vl_lic_store_get();
  if (isset($store[$id])) {
    unset($store[$id]);
    vl_lic_store_set($store);
    
    // Also clean up any associated profiles and conversations
    $profiles = get_option('vl_hub_profiles', []);
    if (isset($profiles[$id])) {
      unset($profiles[$id]);
      update_option('vl_hub_profiles', $profiles);
    }
    
    // Clean up conversations for this license
    $conversations = get_option('vl_hub_conversations', []);
    if (is_array($conversations)) {
      $license_key = $store[$id]['key'] ?? '';
      foreach ($conversations as $conv_id => $conv_data) {
        if ($conv_data['license'] === $license_key) {
          unset($conversations[$conv_id]);
        }
      }
      update_option('vl_hub_conversations', $conversations);
    }
    
    wp_redirect(add_query_arg(['page'=>'vl-licenses','deleted'=>'1'], admin_url('admin.php'))); exit;
  }
  
  wp_redirect(add_query_arg(['page'=>'vl-licenses','err'=>'not_found'], admin_url('admin.php'))); exit;
});

/* =======================================================================
 * Licenses Screen
 * ===================================================================== */
function vl_licenses_screen() {
  if (!current_user_can('manage_options')) return;
  $store = vl_lic_store_get();
  $just  = get_transient('vl_lic_last_created'); if ($just) delete_transient('vl_lic_last_created');

  ?>
  <div class="wrap">
    <h1>Luna Licenses</h1>

    <?php if ($just): ?>
      <div class="notice notice-success">
        <p><strong>License created for <?php echo esc_html($just['client']); ?></strong></p>
        <p>Give this key to the client (shown once):</p>
        <p style="font-family:monospace;font-size:16px;"><code><?php echo esc_html($just['key']); ?></code></p>
        <?php if (!empty($just['site'])): ?>
          <p>Intended site: <a href="<?php echo esc_url($just['site']); ?>" target="_blank" rel="noopener"><?php echo esc_html($just['site']); ?></a></p>
        <?php endif; ?>
      </div>
    <?php endif; ?>

    <?php if (isset($_GET['err']) && $_GET['err'] === 'missing_key'): ?>
      <div class="notice notice-error"><p><strong>License key is required.</strong></p></div>
    <?php endif; ?>
    <?php if (isset($_GET['updated'])): ?>
      <div class="notice notice-success"><p>License updated.</p></div>
    <?php endif; ?>
    <?php if (isset($_GET['deleted'])): ?>
      <div class="notice notice-success"><p>License deleted successfully.</p></div>
    <?php endif; ?>
    <?php if (isset($_GET['err']) && $_GET['err'] === 'missing_id'): ?>
      <div class="notice notice-error"><p><strong>License ID is required for deletion.</strong></p></div>
    <?php endif; ?>
    <?php if (isset($_GET['err']) && $_GET['err'] === 'not_found'): ?>
      <div class="notice notice-error"><p><strong>License not found.</strong></p></div>
    <?php endif; ?>

    <h2>Create a New License</h2>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-bottom:24px;">
      <?php wp_nonce_field('vl_lic_generate'); ?>
      <input type="hidden" name="action" value="vl_lic_generate" />
      <table class="form-table" role="presentation">
        <tr>
          <th scope="row"><label for="vl_lic_client">Client / Website Name</label></th>
          <td><input type="text" id="vl_lic_client" name="client" class="regular-text" placeholder="Commonwealth Health Services" required></td>
        </tr>
        <tr>
          <th scope="row"><label for="vl_lic_site">Site URL (optional)</label></th>
          <td><input type="url" id="vl_lic_site" name="site" class="regular-text code" placeholder="https://example.com"></td>
        </tr>
      </table>
      <?php submit_button('Generate License'); ?>
    </form>

    <h2>Register Existing Key</h2>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-bottom:24px;">
      <?php wp_nonce_field('vl_lic_register_existing'); ?>
      <input type="hidden" name="action" value="vl_lic_register_existing" />
      <table class="form-table" role="presentation">
        <tr>
          <th scope="row"><label for="vl_lic_client2">Client / Website Name</label></th>
          <td><input type="text" id="vl_lic_client2" name="client" class="regular-text" placeholder="Commonwealth Health Services" required></td>
        </tr>
        <tr>
          <th scope="row"><label for="vl_lic_site2">Site URL (optional)</label></th>
          <td><input type="url" id="vl_lic_site2" name="site" class="regular-text code" placeholder="https://example.com"></td>
        </tr>
        <tr>
          <th scope="row"><label for="vl_lic_key2">License Key</label></th>
          <td><input type="text" id="vl_lic_key2" name="key" class="regular-text code" placeholder="VL-XXXX-XXXX-XXXX" required></td>
        </tr>
      </table>
      <?php submit_button('Register Key', 'secondary'); ?>
    </form>

    <h2 style="margin-top:24px;">Issued Licenses</h2>
    <table class="widefat striped">
      <thead>
        <tr>
          <th>Client</th>
          <th>Key</th>
          <th>Intended Site</th>
          <th>Status</th>
          <th>Created</th>
          <th>Last Seen</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <?php if (!$store): ?>
          <tr><td colspan="7">No licenses yet.</td></tr>
        <?php else: foreach ($store as $row): ?>
          <?php
            $last    = !empty($row['last_seen']) ? (int)$row['last_seen'] : 0;
            $created = !empty($row['created']) ? (int)$row['created'] : 0;
            $last_str    = $last ? date_i18n('Y-m-d H:i', $last) : '—';
            $created_str = $created ? date_i18n('Y-m-d H:i', $created) : '—';
            $profile_url = add_query_arg(['page'=>'vl-client-profile','id'=>$row['id']], admin_url('admin.php'));
          ?>
          <tr>
            <td><a href="<?php echo esc_url($profile_url); ?>"><strong><?php echo esc_html($row['client']); ?></strong></a></td>
            <td><code><?php echo esc_html(vl_lic_redact((string)$row['key'])); ?></code></td>
            <td>
              <?php if (!empty($row['site'])): ?>
                <a href="<?php echo esc_url($row['site']); ?>" target="_blank" rel="noopener"><?php echo esc_html($row['site']); ?></a>
              <?php else: ?>—<?php endif; ?>
            </td>
            <td><?php echo vl_status_pill_from_row($row); ?></td>
            <td><?php echo esc_html($created_str); ?></td>
            <td><?php echo esc_html($last_str); ?></td>
            <td>
              <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline;margin-right:8px;">
                <?php wp_nonce_field('vl_lic_toggle'); ?>
                <input type="hidden" name="action" value="vl_lic_toggle" />
                <input type="hidden" name="id" value="<?php echo esc_attr($row['id']); ?>" />
                <?php if (!empty($row['active'])): ?>
                  <input type="hidden" name="make_active" value="">
                  <button class="button">Disable</button>
                <?php else: ?>
                  <input type="hidden" name="make_active" value="1">
                  <button class="button button-primary">Enable</button>
                <?php endif; ?>
              </form>
              
              <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline;" 
                    onsubmit="return confirm('Are you sure you want to delete this license? This action cannot be undone.');">
                <?php wp_nonce_field('vl_lic_delete'); ?>
                <input type="hidden" name="action" value="vl_lic_delete" />
                <input type="hidden" name="id" value="<?php echo esc_attr($row['id']); ?>" />
                <button class="button button-link-delete" style="color:#a00;">Delete</button>
              </form>
            </td>
          </tr>
        <?php endforeach; endif; ?>
      </tbody>
    </table>
  </div>
  <?php
}

/* =======================================================================
 * REST endpoints (client-initiated activate/heartbeat)
 * ===================================================================== */
add_action('rest_api_init', function () {

  register_rest_route('vl-license/v1', '/activate', [
    'methods'  => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function ($req) {
      $license = trim((string)$req->get_param('license'));
      $site    = esc_url_raw((string)$req->get_param('site_url'));
      $name    = sanitize_text_field((string)$req->get_param('site_name'));
      $wpv     = sanitize_text_field((string)$req->get_param('wp_version'));
      $pv      = sanitize_text_field((string)$req->get_param('plugin_version'));

      if (!$license || !$site) return new WP_REST_Response(['ok'=>false,'error'=>'missing_params'], 400);

      $store = vl_lic_store_get();
      $found_id = null;
      foreach ($store as $id => $row) {
        if (!empty($row['key']) && hash_equals($row['key'], $license)) { $found_id = $id; break; }
      }
      if (!$found_id) return new WP_REST_Response(['ok'=>false,'error'=>'invalid_license'], 403);
      if (empty($store[$found_id]['active'])) return new WP_REST_Response(['ok'=>false,'error'=>'revoked'], 403);

      $store[$found_id]['site']           = $site ?: ($store[$found_id]['site'] ?? '');
      $store[$found_id]['site_name']      = $name ?: ($store[$found_id]['site_name'] ?? '');
      $store[$found_id]['wp_version']     = $wpv  ?: ($store[$found_id]['wp_version'] ?? '');
      $store[$found_id]['plugin_version'] = $pv   ?: ($store[$found_id]['plugin_version'] ?? '');
      $store[$found_id]['last_seen']      = time();
      vl_lic_store_set($store);
      
      // Also update the Hub profile with basic WordPress data
      vl_update_hub_profile_basic_data($found_id, $site, $license);

      return new WP_REST_Response(['ok'=>true, 'interval_sec'=>3600], 200);
    }
  ]);

  register_rest_route('vl-license/v1', '/heartbeat', [
    'methods'  => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function ($req) {
      $license = trim((string)$req->get_param('license'));
      $site    = esc_url_raw((string)$req->get_param('site_url'));
      $wpv     = sanitize_text_field((string)$req->get_param('wp_version'));
      $pv      = sanitize_text_field((string)$req->get_param('plugin_version'));

      $store = vl_lic_store_get();
      $found_id = null;
      foreach ($store as $id => $row) {
        if (!empty($row['key']) && hash_equals($row['key'], $license)) { $found_id = $id; break; }
      }
      if (!$found_id) return new WP_REST_Response(['ok'=>false,'error'=>'invalid_license'], 403);
      if (empty($store[$found_id]['active'])) return new WP_REST_Response(['ok'=>false,'error'=>'revoked'], 403);

      $known = (string)($store[$found_id]['site'] ?? '');
      if ($known && $site && strcasecmp($known, $site) !== 0) {
        $store[$found_id]['site_url_conflict'] = $site; // soft flag
      } else if ($site) {
        $store[$found_id]['site'] = $site;
      }
      if ($wpv) $store[$found_id]['wp_version'] = $wpv;
      if ($pv)  $store[$found_id]['plugin_version'] = $pv;
      $store[$found_id]['last_seen'] = time();
      vl_lic_store_set($store);
      
      // Also update the Hub profile with basic WordPress data
      vl_update_hub_profile_basic_data($found_id, $site, $license);

      return new WP_REST_Response(['ok'=>true], 200);
    }
  ]);

});

/* =======================================================================
 * Client Profile cache helpers
 * ===================================================================== */
function vl_client_profile_cache_get(string $id): array {
  $opt = get_option(VL_PROFILE_CACHE_OPTION, []);
  if (!is_array($opt)) $opt = [];
  return $opt[$id] ?? [];
}
function vl_client_profile_cache_set(string $id, array $data): void {
  $opt = get_option(VL_PROFILE_CACHE_OPTION, []);
  if (!is_array($opt)) $opt = [];
  $opt[$id] = ['t'=>time(), 'data'=>$data];
  update_option(VL_PROFILE_CACHE_OPTION, $opt, false);
}
function vl_client_profile_cache_fresh(array $blob): bool {
  if (!isset($blob['t'])) return false;
  return (time() - (int)$blob['t']) <= VL_PROFILE_CACHE_TTL;
}
function vl_client_profile_cache_clear(string $id): void {
  $opt = get_option(VL_PROFILE_CACHE_OPTION, []);
  if (!is_array($opt)) $opt = [];
  if (isset($opt[$id])) { unset($opt[$id]); update_option(VL_PROFILE_CACHE_OPTION, $opt, false); }
}

/* =======================================================================
 * Fetchers (site snapshot + content + users + AI chats)
 * ===================================================================== */
function vl_fetch_client_all(string $site, string $license = ''): array {
  $site = rtrim($site, '/');
  if (!$site) return [];

  $headers = [];
  if ($license) $headers['X-Luna-License'] = $license;

  // 1) Widget-only site snapshot (and demo endpoint if present)
  $urls = [
    $site . '/wp-json/luna_widget/v1/system/site',
    $site . '/wp-json/commonwealth/v1/system/site',
  ];
  $merged = [];

  foreach ($urls as $u) {
    $res = wp_remote_get($u, [ 'timeout'=>12, 'redirection'=>3, 'headers'=>$headers ]);
    if (is_wp_error($res)) continue;
    $code = wp_remote_retrieve_response_code($res);
    if ($code < 200 || $code >= 300) continue;
    $json = json_decode(wp_remote_retrieve_body($res), true);
    if (is_array($json)) {
      foreach ($json as $k => $v) {
        if (!isset($merged[$k])) $merged[$k] = $v;
      }
    }
  }

  // 2) Content + Users (secured via license on widget endpoint)
  $add = function($path) use ($site,$headers){
    $res = wp_remote_get($site . $path, [ 'timeout'=>15, 'headers'=>$headers ]);
    if (is_wp_error($res)) return null;
    $code = wp_remote_retrieve_response_code($res);
    if ($code < 200 || $code >= 300) return null;
    return json_decode(wp_remote_retrieve_body($res), true);
  };
  $posts = $add('/wp-json/luna_widget/v1/content/posts?per_page=100&page=1');
  $pages = $add('/wp-json/luna_widget/v1/content/pages?per_page=100&page=1');
  $users = $add('/wp-json/luna_widget/v1/users?per_page=100&page=1');

  if (is_array($posts)) $merged['_posts'] = $posts;
  if (is_array($pages)) $merged['_pages'] = $pages;
  if (is_array($users)) $merged['_users'] = $users;

  return $merged;
}

/** Conversations list (live; no caching) */
// Fetch AI conversations list from client site (robust auth & endpoints)
function vl_fetch_client_chats(string $site, string $license=''): array {
  $site = rtrim($site, '/');
  if (!$site) return ['items'=>[]];

  $ts = time(); // cache-bust
  $paths = [
    "/wp-json/luna_widget/v1/conversations?per_page=200&page=1&_=$ts",
    "/wp-json/luna_widget/v1/chats?per_page=200&page=1&_=$ts",
  ];

  // Try: header → query param → POST JSON
  $styles = [
    function($url) use($license) {
      $headers = $license ? ['X-Luna-License' => $license] : [];
      return wp_remote_get($url, ['timeout'=>15,'headers'=>$headers]);
    },
    function($url) use($license) {
      if (!$license) return new WP_Error('no_license');
      $sep = (strpos($url,'?')!==false)?'&':'?';
      return wp_remote_get($url . $sep . 'license=' . rawurlencode($license), ['timeout'=>15]);
    },
    function($url) use($license) {
      if (!$license) return new WP_Error('no_license');
      return wp_remote_post($url, [
        'timeout' => 15,
        'headers' => ['Content-Type'=>'application/json'],
        'body'    => wp_json_encode(['license'=>$license]),
      ]);
    },
  ];

  foreach ($paths as $path) {
    $url = $site . $path;
    foreach ($styles as $call) {
      $res = $call($url);
      if (is_wp_error($res)) continue;
      $code = (int) wp_remote_retrieve_response_code($res);
      if ($code < 200 || $code >= 300) continue;

      $json = json_decode(wp_remote_retrieve_body($res), true);
      if (!is_array($json)) continue;

      // Normalize shape
      if (isset($json['items']) && is_array($json['items'])) return $json;
      if (isset($json['data'])  && is_array($json['data']))  return ['items'=>$json['data']];
      if (array_keys($json) === range(0, count($json)-1))    return ['items'=>$json]; // plain array
    }
  }

  return ['items'=>[]];
}

/** Single conversation detail (live) */
function vl_fetch_client_chat_detail(string $site, string $license, $conv_id) : array {
  $site = rtrim($site, '/');
  if (!$site || !$conv_id) return ['ok'=>false,'error'=>'missing_params'];

  $paths = [
    '/wp-json/luna_widget/v1/chats/' . rawurlencode((string)$conv_id),
    '/wp-json/luna_widget/v1/conversations/' . rawurlencode((string)$conv_id),
    '/wp-json/luna_widget/v1/conversation/' . rawurlencode((string)$conv_id),
  ];

  $styles = [
    function($url) use($license) {
      $headers = $license ? ['X-Luna-License' => $license] : [];
      return wp_remote_get($url, ['timeout'=>15,'headers'=>$headers]);
    },
    function($url) use($license) {
      if (!$license) return new WP_Error('no_license');
      $sep = (strpos($url,'?')!==false)?'&':'?';
      return wp_remote_get($url . $sep . 'license=' . rawurlencode($license), ['timeout'=>15]);
    },
    function($url) use($license) {
      if (!$license) return new WP_Error('no_license');
      return wp_remote_post($url, [
        'timeout' => 15,
        'headers' => ['Content-Type'=>'application/json'],
        'body'    => wp_json_encode(['license'=>$license]),
      ]);
    },
  ];

  $last_http = 0;
  foreach ($paths as $path) {
    $url = $site . $path;
    foreach ($styles as $call) {
      $res = $call($url);
      if (is_wp_error($res)) { $last_http = 0; continue; }
      $code = (int) wp_remote_retrieve_response_code($res);
      $last_http = $code;
      if ($code < 200 || $code >= 300) continue;

      $body = json_decode(wp_remote_retrieve_body($res), true);
      if (!is_array($body)) continue;

      // normalize
      $out = [
        'ok'         => true,
        'id'         => $body['id']         ?? (string)$conv_id,
        'started_at' => $body['started_at'] ?? '',
        'transcript' => [],
      ];
      if (!$out['started_at'] && isset($body['started_ts']) && is_numeric($body['started_ts'])) {
        $out['started_at'] = date_i18n('Y-m-d H:i', (int)$body['started_ts']);
      }

      $tx = [];
      if (!empty($body['transcript']) && is_array($body['transcript'])) $tx = $body['transcript'];
      elseif (!empty($body['turns'])    && is_array($body['turns']))    $tx = $body['turns'];
      elseif (!empty($body['messages']) && is_array($body['messages'])) $tx = $body['messages'];

      $out['transcript'] = array_values(array_filter($tx, function($t){
        return is_array($t) && (isset($t['user']) || isset($t['assistant']) || isset($t['role']) || isset($t['content']));
      }));

      // role-based → user/assistant
      foreach ($out['transcript'] as &$turn) {
        if (isset($turn['role']) && isset($turn['content'])) {
          if ($turn['role'] === 'user' && !isset($turn['user']))        $turn['user'] = $turn['content'];
          if ($turn['role'] !== 'user' && !isset($turn['assistant']))   $turn['assistant'] = $turn['content'];
        }
      }

      return $out;
    }
  }
  return ['ok'=>false,'error'=>'http_'.$last_http];
}

/* =======================================================================
 * Render Client Profile (incl. Security tab + AI + Cloud)
 * ===================================================================== */
function vl_render_client_profile() {
  if (!current_user_can('manage_options')) return;

  $id     = sanitize_text_field($_GET['id'] ?? '');
  $tab    = sanitize_key($_GET['tab'] ?? 'overview');
  $nocache= !empty($_GET['nocache']);

  $store = vl_lic_store_get();
  if (!$id || empty($store[$id])) {
    echo '<div class="wrap"><h1>Client Profile</h1><p>Unknown client.</p></div>'; return;
  }
  $row    = $store[$id];
  $site   = (string)($row['site'] ?? '');
  $license= (string)($row['key'] ?? '');

  if ($nocache) vl_client_profile_cache_clear($id);

  // Cached fetch (for site snapshot, not for AI chats)
  $cache_blob = vl_client_profile_cache_get($id);
  if (!vl_client_profile_cache_fresh($cache_blob)) {
    $data = vl_fetch_client_all($site, $license);
    vl_client_profile_cache_set($id, $data);
  } else {
    $data = $cache_blob['data'] ?? [];
  }

  $tabs = [
    'overview' => 'Overview',
    'posts'    => 'Posts',
    'pages'    => 'Pages',
    'plugins'  => 'Plugins',
    'themes'   => 'Themes',
    'users'    => 'Users',
    'security' => 'Security',
    'keywords' => 'Keywords',
    'ai'       => 'AI Chats',
    'cloud'    => 'Cloud Connections',
  ];

  $make_tab = function($slug,$label) use ($id,$tab){
    $url = add_query_arg(['page'=>'vl-client-profile','id'=>$id,'tab'=>$slug], admin_url('admin.php'));
    printf('<a href="%s" class="nav-tab %s">%s</a>',
      esc_url($url), $slug===$tab?'nav-tab-active':'', esc_html($label)
    );
  };

  $refresh_url = add_query_arg(['page'=>'vl-client-profile','id'=>$id,'tab'=>$tab,'nocache'=>1], admin_url('admin.php'));

  ?>
  <div class="wrap">
    <h1>Client: <?php echo esc_html($row['client']); ?></h1>
    <p>
      <?php if ($site): ?>
        <a href="<?php echo esc_url($site); ?>" target="_blank" rel="noopener"><?php echo esc_html($site); ?></a>
      <?php else: ?>—<?php endif; ?>
      &nbsp;•&nbsp;<a href="<?php echo esc_url($refresh_url); ?>">Force refresh</a>
    </p>
    <h2 class="nav-tab-wrapper" style="margin-top:12px;">
      <?php foreach ($tabs as $slug=>$label) $make_tab($slug,$label); ?>
    </h2>
  <?php

  switch ($tab) {
    case 'posts':
      $list = (array)($data['_posts']['items'] ?? []);
      echo '<h2>Posts</h2>';
      if (!$list) { echo '<p>No posts found.</p>'; break; }
      echo '<table class="widefat striped"><thead><tr><th>ID</th><th>Title</th><th>Categories</th><th>Tags</th><th>Date</th></tr></thead><tbody>';
      foreach ($list as $p) {
        printf('<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
          (int)$p['id'], esc_html($p['title']), esc_html(implode(', ', $p['categories']??[])),
          esc_html(implode(', ', $p['tags']??[])), esc_html($p['date']??'')
        );
      }
      echo '</tbody></table>';
      break;

    case 'pages':
      $list = (array)($data['_pages']['items'] ?? []);
      echo '<h2>Pages</h2>';
      if (!$list) { echo '<p>No pages found.</p>'; break; }
      echo '<table class="widefat striped"><thead><tr><th>ID</th><th>Title</th><th>Slug</th><th>Date</th></tr></thead><tbody>';
      foreach ($list as $p) {
        printf('<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>',
          (int)$p['id'], esc_html($p['title']), esc_html($p['slug']), esc_html($p['date']??'')
        );
      }
      echo '</tbody></table>';
      break;

    case 'plugins':
      $list = (array)($data['plugins'] ?? []);
      echo '<h2>Plugins</h2>';
      if (!$list) { echo '<p>No plugins found.</p>'; break; }
      echo '<table class="widefat striped"><thead><tr><th>Name</th><th>Slug</th><th>Version</th><th>Active</th><th>Update</th></tr></thead><tbody>';
      foreach ($list as $p) {
        printf('<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s%s</td></tr>',
          esc_html($p['name']??''), esc_html($p['slug']??''), esc_html($p['version']??''),
          !empty($p['active'])?'Yes':'No',
          !empty($p['update_available'])?'Available':'—',
          !empty($p['new_version'])?(' ('.esc_html($p['new_version']).')'):''
        );
      }
      echo '</tbody></table>';
      break;

    case 'themes':
      $list = (array)($data['themes'] ?? []);
      echo '<h2>Themes</h2>';
      if (!$list) { echo '<p>No themes found.</p>'; break; }
      echo '<table class="widefat striped"><thead><tr><th>Name</th><th>Stylesheet</th><th>Version</th><th>Active</th><th>Update</th></tr></thead><tbody>';
      foreach ($list as $t) {
        printf('<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s%s</td></tr>',
          esc_html($t['name']??''), esc_html($t['stylesheet']??''), esc_html($t['version']??''),
          !empty($t['is_active'])?'Yes':'No',
          !empty($t['update_available'])?'Available':'—',
          !empty($t['new_version'])?(' ('.esc_html($t['new_version']).')'):''
        );
      }
      echo '</tbody></table>';
      break;

    case 'users':
      $list = (array)($data['_users']['items'] ?? []);
      echo '<h2>Users</h2>';
      if (!$list) { echo '<p>No users found.</p>'; break; }
      echo '<table class="widefat striped"><thead><tr><th>ID</th><th>Username</th><th>Name</th><th>Email</th></tr></thead><tbody>';
      foreach ($list as $u) {
        printf('<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>',
          (int)$u['id'], esc_html($u['username']), esc_html($u['name']), esc_html($u['email'])
        );
      }
      echo '</tbody></table>';
      break;

        case 'security':
      echo '<h2>Security</h2>';

      // 🔑 Read the Hub-side stored profile for THIS license id (lic_…)
      $all_profiles = get_option('vl_hub_profiles', []);
      if (!is_array($all_profiles)) $all_profiles = [];

      // $id is the lic_… from the querystring and license table; that's our key
      $profile = (isset($all_profiles[$id]) && is_array($all_profiles[$id])) ? $all_profiles[$id] : [];

      // If you ever stored by human key (VL-…): optional fallback (usually not needed)
      if (!$profile && !empty($license)) {
        if (!empty($all_profiles[$license]) && is_array($all_profiles[$license])) {
          $profile = $all_profiles[$license];
        }
      }

      // Debug: Show what we're looking for and what we found
      echo '<div style="background:#f0f0f0;padding:10px;margin:10px 0;border-left:4px solid #0073aa;">';
      echo '<strong>Debug Info:</strong><br>';
      echo 'Looking for license ID: <code>' . esc_html($id) . '</code><br>';
      echo 'Human license key: <code>' . esc_html($license) . '</code><br>';
      echo 'Available profile keys: <code>' . esc_html(implode(', ', array_keys($all_profiles))) . '</code><br>';
      echo 'Profile found: ' . (!empty($profile) ? 'Yes' : 'No') . '<br>';
      if (!empty($profile['security'])) {
        echo 'Security data found: Yes<br>';
        echo 'Security keys: <code>' . esc_html(implode(', ', array_keys($profile['security']))) . '</code>';
      } else {
        echo 'Security data found: No';
      }
      echo '</div>';

      // Pull the security slice (new canonical shape lives under top-level ["security"])
      $sec = (array)($profile['security'] ?? []);
      // Normalize a few aliases for older shapes
      $tls = (array)($sec['tls'] ?? $profile['tls'] ?? []);
      $fw  = (array)($sec['waf'] ?? $sec['firewall'] ?? []);
      $det = (array)($sec['ids'] ?? $sec['detection'] ?? []);
      $auth= (array)($sec['auth'] ?? []);
      $dom = (array)($sec['domain'] ?? $profile['domain'] ?? []);
      $db  = (array)($sec['database'] ?? []);
      $svc = (array)($sec['services'] ?? []);

      // --- TLS/SSL ---
      echo '<h3>TLS/SSL <button onclick="validateAllFields()" class="button button-small" style="margin-left:10px;">Validate Fields</button></h3>';
      echo '<table class="widefat striped"><tbody>';
      $tls_ver = $tls['version'] ?? null;
      if ($tls_ver) {
        echo '<tr><th style="width:240px;">TLS Engine/Version <span class="validation-status" data-field="tls_version">⏳</span></th><td>'.esc_html($tls_ver).'</td></tr>';
      }
      $rows = [
        'tls_status' => ['label' => 'Status', 'value' => (isset($tls['valid']) ? ($tls['valid'] ? 'Valid' : 'Invalid') : '')],
        'tls_issuer' => ['label' => 'Issuer', 'value' => $tls['issuer'] ?? ''],
        'tls_provider_guess' => ['label' => 'Provider Guess', 'value' => $tls['provider_guess'] ?? ''],
        'tls_valid_from' => ['label' => 'Valid From', 'value' => $tls['valid_from'] ?? ''],
        'tls_valid_to' => ['label' => 'Valid To', 'value' => $tls['valid_to'] ?? ''],
        'tls_host' => ['label' => 'Host', 'value' => $tls['host'] ?? ''],
      ];
      foreach ($rows as $field => $data) { 
        if ($data['value'] !== '' && $data['value'] !== null) {
          echo '<tr><th>'.esc_html($data['label']).' <span class="validation-status" data-field="'.esc_attr($field).'">⏳</span></th><td>'.esc_html($data['value']).'</td></tr>';
        }
      }
      echo '</tbody></table>';

      // --- Firewall / WAF ---
      echo '<h3 style="margin-top:20px;">Firewall / WAF</h3>';
      if ($fw) {
        echo '<table class="widefat striped"><tbody>';
        $rows = [
          'waf_provider' => ['label' => 'Provider', 'value' => $fw['provider'] ?? ''],
          'waf_last_audit' => ['label' => 'Last Audit', 'value' => $fw['last_audit'] ?? ''],
        ];
        foreach ($rows as $field => $data) { 
          if ($data['value']) {
            echo '<tr><th style="width:240px;">'.esc_html($data['label']).' <span class="validation-status" data-field="'.esc_attr($field).'">⏳</span></th><td>'.esc_html($data['value']).'</td></tr>';
          }
        }
        echo '</tbody></table>';
      } else { echo '<p>No firewall data available.</p>'; }

      // --- Threat Detection / IDS ---
      echo '<h3 style="margin-top:20px;">Threat Detection / IDS</h3>';
      if ($det) {
        echo '<table class="widefat striped"><tbody>';
        $rows = [
          'ids_provider' => ['label' => 'IDS / IPS', 'value' => $det['ids_ips'] ?? ($det['provider'] ?? '')],
          'ids_last_scan' => ['label' => 'Last Scan', 'value' => $det['last_scan'] ?? ''],
          'ids_result' => ['label' => 'Last Result', 'value' => $det['result'] ?? ''],
          'ids_schedule' => ['label' => 'Scan Schedule', 'value' => $det['schedule'] ?? ''],
        ];
        foreach ($rows as $field => $data) { 
          if ($data['value']) {
            echo '<tr><th style="width:240px;">'.esc_html($data['label']).' <span class="validation-status" data-field="'.esc_attr($field).'">⏳</span></th><td>'.esc_html($data['value']).'</td></tr>';
          }
        }
        if (!empty($det['malware_scans']) && is_array($det['malware_scans'])) {
          echo '<tr><th style="width:240px;">Malware Scans Detail</th><td>';
          echo '<table class="widefat striped"><tbody>';
          foreach ($det['malware_scans'] as $mk=>$mv) {
            if (is_bool($mv)) $mv = $mv ? 'Yes' : 'No';
            echo '<tr><th style="width:180px;">'.esc_html(ucwords(str_replace('_',' ',$mk))).'</th><td>'.esc_html((string)$mv).'</td></tr>';
          }
          echo '</tbody></table>';
          echo '</td></tr>';
        }
        echo '</tbody></table>';
      } else { echo '<p>No detection data available.</p>'; }

      // --- Authentication ---
      echo '<h3 style="margin-top:20px;">Authentication</h3>';
      if ($auth) {
        echo '<table class="widefat striped"><tbody>';
        $auth_fields = [
          'auth_mfa' => ['label' => 'MFA', 'value' => $auth['mfa'] ?? ''],
          'auth_password_policy' => ['label' => 'Password Policy', 'value' => $auth['password_policy'] ?? ''],
          'auth_session_timeout' => ['label' => 'Session Timeout', 'value' => $auth['session_timeout'] ?? ''],
          'auth_sso_providers' => ['label' => 'SSO Providers', 'value' => $auth['sso_providers'] ?? ''],
        ];
        foreach ($auth_fields as $field => $data) {
          if ($data['value']) {
            echo '<tr><th style="width:240px;">'.esc_html($data['label']).' <span class="validation-status" data-field="'.esc_attr($field).'">⏳</span></th><td>'.esc_html($data['value']).'</td></tr>';
          }
        }
        echo '</tbody></table>';
      } else { echo '<p>No authentication data available.</p>'; }

      // --- Domain ---
      echo '<h3 style="margin-top:20px;">Domain</h3>';
      if ($dom) {
        echo '<table class="widefat striped"><tbody>';
        $rows = [
          'domain_registrar' => ['label' => 'Registrar', 'value' => $dom['registrar'] ?? ''],
          'domain_registered_on' => ['label' => 'Registered On', 'value' => $dom['registered_on'] ?? ''],
          'domain_renewal_date' => ['label' => 'Renewal Date', 'value' => $dom['renewal_date'] ?? ''],
          'domain_auto_renew' => ['label' => 'Auto Renew', 'value' => (isset($dom['auto_renew']) ? ($dom['auto_renew'] ? 'Yes' : 'No') : '')],
        ];
        foreach ($rows as $field => $data) { 
          if ($data['value'] !== '' && $data['value'] !== null) {
            echo '<tr><th style="width:240px;">'.esc_html($data['label']).' <span class="validation-status" data-field="'.esc_attr($field).'">⏳</span></th><td>'.esc_html($data['value']).'</td></tr>';
          }
        }

        // DNS (freeform or structured)
        if (!empty($dom['dns']['records']) && is_array($dom['dns']['records'])) {
          echo '<tr><th>DNS Records <span class="validation-status" data-field="domain_dns_records">⏳</span></th><td><table class="widefat striped"><thead><tr><th>Type</th><th>Name</th><th>Value</th><th>Priority</th></tr></thead><tbody>';
          foreach ($dom['dns']['records'] as $r) {
            printf('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
              esc_html($r['type']??''), esc_html($r['name']??''), esc_html($r['value']??''), isset($r['priority'])?esc_html((string)$r['priority']):'—'
            );
          }
          echo '</tbody></table></td></tr>';
        } elseif (!empty($dom['dns_records'])) {
          echo '<tr><th>DNS Records <span class="validation-status" data-field="domain_dns_records">⏳</span></th><td><pre>'.esc_html((string)$dom['dns_records']).'</pre></td></tr>';
        }

        echo '</tbody></table>';
      } else {
        echo '<p>No domain data available.</p>';
      }

      // --- Database ---
      echo '<h3 style="margin-top:20px;">Database</h3>';
      if ($db) {
        foreach ($db as $dbk=>$dbv) {
          if (!is_array($dbv)) continue;
          echo '<h4>'.esc_html(ucwords(str_replace('_',' ',$dbk))).'</h4>';
          echo '<table class="widefat striped"><tbody>';
          foreach ($dbv as $k=>$v) {
            if (is_bool($v)) $v = $v ? 'Yes' : 'No';
            echo '<tr><th style="width:240px;">'.esc_html(ucwords(str_replace('_',' ',$k))).'</th><td>'.esc_html((string)$v).'</td></tr>';
          }
          echo '</tbody></table>';
        }
      } else { echo '<p>No database info available.</p>'; }

      // --- Services ---
      echo '<h3 style="margin-top:20px;">Services</h3>';
      if ($svc) {
        foreach ($svc as $svc_k=>$svc_v) {
          if (!is_array($svc_v)) continue;
          echo '<h4>'.esc_html(ucwords(str_replace('_',' ',$svc_k))).'</h4>';
          echo '<table class="widefat striped"><tbody>';
          foreach ($svc_v as $k=>$v) {
            if (is_bool($v)) $v = $v ? 'Yes' : 'No';
            echo '<tr><th style="width:240px;">'.esc_html(ucwords(str_replace('_',' ',$k))).'</th><td>'.esc_html((string)$v).'</td></tr>';
          }
          echo '</tbody></table>';
        }
      } else { echo '<p>No services info available.</p>'; }

      // Add JavaScript for real-time validation
      echo '<script>
      function validateAllFields() {
        const license = "' . esc_js($license) . '";
        const fields = [
          "tls_status", "tls_version", "tls_issuer", "tls_provider_guess",
          "tls_valid_from", "tls_valid_to", "tls_host",
          "waf_provider", "waf_last_audit",
          "ids_provider", "ids_last_scan", "ids_result", "ids_schedule",
          "auth_mfa", "auth_password_policy", "auth_session_timeout", "auth_sso_providers",
          "domain_registrar", "domain_registered_on", "domain_renewal_date", "domain_auto_renew", "domain_dns_records"
        ];
        
        fields.forEach(field => {
          fetch("/wp-json/luna_widget/v1/validate/field", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Luna-License": license
            },
            body: JSON.stringify({ field: field })
          })
          .then(response => response.json())
          .then(data => {
            updateFieldValidation(field, data);
          })
          .catch(error => {
            console.error("Validation error for field " + field + ":", error);
            updateFieldValidation(field, { valid: false, error: "Network error" });
          });
        });
      }
      
      function updateFieldValidation(field, validation) {
        const fieldElement = document.querySelector(`[data-field="${field}"]`);
        if (fieldElement) {
          if (validation.valid) {
            fieldElement.innerHTML = \'<span style="color:#057a25;font-weight:bold;">✓</span>\';
            fieldElement.title = "Field mapped correctly - Value: " + (validation.value || "N/A");
          } else {
            fieldElement.innerHTML = \'<span style="color:#a50000;font-weight:bold;">✗</span>\';
            fieldElement.title = validation.error || "Field not mapped";
          }
        }
      }
      
      // Run validation on page load
      document.addEventListener("DOMContentLoaded", function() {
        validateAllFields();
      });
      </script>';

      break;

    case 'keywords':
      echo '<h2>Keywords</h2>';
      
      // Get keywords from Hub profile
      $all_profiles = get_option('vl_hub_profiles', []);
      $profile = $all_profiles[$id] ?? [];
      $keywords = $profile['keywords'] ?? [];
      $keywords_updated = $profile['keywords_updated_at'] ?? '';
      
      if (empty($keywords)) {
        echo '<p>No keyword mappings configured yet.</p>';
        echo '<p><em>Keywords are managed on the client site in the Luna Chat Widget admin area.</em></p>';
      } else {
        echo '<p><strong>Last updated:</strong> ' . ($keywords_updated ? esc_html($keywords_updated) : 'Unknown') . '</p>';
        
        foreach ($keywords as $category => $category_keywords) {
          echo '<h3>' . esc_html(ucfirst($category)) . ' Keywords</h3>';
          echo '<table class="widefat striped">';
          echo '<thead><tr><th>Action</th><th>Keywords</th></tr></thead>';
          echo '<tbody>';
          
          foreach ($category_keywords as $action => $terms) {
            echo '<tr>';
            echo '<td><strong>' . esc_html(ucfirst($action)) . '</strong></td>';
            echo '<td>' . esc_html(implode(', ', $terms)) . '</td>';
            echo '</tr>';
          }
          
          echo '</tbody></table>';
        }
      }
      break;

    case 'ai':
      echo '<h2>AI Chats</h2>';
      if (!$site) { echo '<p>No site URL recorded yet.</p>'; break; }

      // Debug: Show what we're looking for (temporarily disabled)
      // echo '<p><strong>Debug Info:</strong></p>';
      // echo '<p>Site: ' . esc_html($site) . '</p>';
      // echo '<p>License: ' . esc_html(substr($license, 0, 8)) . '...</p>';

      // Live fetch (not cached) - try both sources
      $chats = vl_fetch_client_chats($site, $license);
      // echo '<p>Client chats fetched: ' . (is_array($chats) ? count($chats) : 'Error') . '</p>';
      
      // Also check Hub-stored conversations
      $hub_conversations = get_option('vl_hub_conversations', []);
      // echo '<p>Hub conversations total: ' . (is_array($hub_conversations) ? count($hub_conversations) : 'Error') . '</p>';
      
      if (is_array($hub_conversations)) {
        $hub_chats = [];
        foreach ($hub_conversations as $conv_id => $conv_data) {
          if ($conv_data['license'] === $license) {
            $hub_chats[] = [
              'id' => $conv_id,
              'started' => $conv_data['started_at'],
              'turns' => count($conv_data['transcript'] ?? []),
              'site' => $conv_data['site'],
            ];
          }
        }
        
        // Merge with client-fetched chats
        if (!empty($hub_chats)) {
          $chats['items'] = array_merge($chats['items'] ?? [], $hub_chats);
        }
      }

      // Small “force refresh” link (reloads this tab)
      $force = add_query_arg(['page'=>'vl-client-profile','id'=>$id,'tab'=>'ai','_'=>time()], admin_url('admin.php'));
      echo '<p><a href="'.esc_url($force).'" class="button">Force Refresh</a></p>';

      if (empty($chats['items'])) { echo '<p>No conversations found.</p>'; break; }

      echo '<table class="widefat striped"><thead><tr><th>ID</th><th>Started</th><th>Turns</th><th>View</th></tr></thead><tbody>';
      foreach ($chats['items'] as $c) {
        $cid   = (string)($c['id'] ?? '');
        // most endpoints give 'started' as ISO; fallback to started_unix
        $when  = '';
        if (!empty($c['started'])) {
          $when = date_i18n('Y-m-d H:i', strtotime($c['started']));
        } elseif (!empty($c['started_unix']) && is_numeric($c['started_unix'])) {
          $when = date_i18n('Y-m-d H:i', (int)$c['started_unix']);
        }
        $turns = (int)($c['turns'] ?? 0);
        $view  = add_query_arg(
          ['page'=>'vl-client-profile','id'=>$id,'tab'=>'ai','conv'=>$cid],
          admin_url('admin.php')
        ) . '#luna-conv';

        printf(
          '<tr><td>%s</td><td>%s</td><td>%d</td><td><a href="%s">Open</a></td></tr>',
          esc_html($cid), esc_html($when), $turns, esc_url($view)
        );
      }
      echo '</tbody></table>';

      // Detail panel
      echo '<div id="luna-conv"></div>';
      if (!empty($_GET['conv'])) {
        $conv_id = sanitize_text_field((string)$_GET['conv']);
        
        // Try Hub-stored conversations first
        $hub_conversations = get_option('vl_hub_conversations', []);
        $detail = null;
        
        if (isset($hub_conversations[$conv_id]) && $hub_conversations[$conv_id]['license'] === $license) {
          $conv_data = $hub_conversations[$conv_id];
          $detail = [
            'ok' => true,
            'id' => $conv_id,
            'started_at' => $conv_data['started_at'],
            'transcript' => $conv_data['transcript'] ?? [],
          ];
        } else {
          // Fallback to client site fetch
          $detail = vl_fetch_client_chat_detail($site, $license, $conv_id);
        }

        echo '<hr/>';
        if (empty($detail['ok'])) {
          echo '<p><em>Could not load conversation: ' . esc_html($detail['error'] ?? 'unknown error') . '.</em></p>';
          break;
        }

        // Started at (prefer ISO; fallback to unix in first turn)
        $started = '';
        if (!empty($detail['started_at'])) {
          $started = (string)$detail['started_at'];
        } elseif (!empty($detail['transcript'][0]['ts']) && is_numeric($detail['transcript'][0]['ts'])) {
          $started = date_i18n('Y-m-d H:i', (int)$detail['transcript'][0]['ts']);
        }

        echo '<h3>Conversation: ' . esc_html((string)($detail['id'] ?? $conv_id)) . '</h3>';
        echo '<p><em>Started: ' . esc_html($started ?: '—') . '</em></p>';

        // Render transcript bubbles
        echo '<div style="border:1px solid #ddd;padding:12px;border-radius:6px;background:#fff;">';
        if (!empty($detail['transcript'])) {
          foreach ($detail['transcript'] as $t) {
            $ts = '';
            if (!empty($t['ts']) && is_numeric($t['ts'])) $ts = date_i18n('Y-m-d H:i', (int)$t['ts']);

            // user turn
            if (isset($t['user']) && $t['user'] !== '') {
              echo '<div style="margin-bottom:10px;">';
              echo '<div><strong>User</strong>' . ($ts ? ' <span style="opacity:.7">'.$ts.'</span>' : '') . '</div>';
              echo '<div>' . esc_html((string)$t['user']) . '</div>';
              echo '</div>';
            }
            // assistant turn
            if (isset($t['assistant']) && $t['assistant'] !== '') {
              echo '<div style="margin-bottom:10px;">';
              echo '<div><strong>Assistant</strong></div>';
              echo '<div>' . esc_html((string)$t['assistant']) . '</div>';
              echo '</div>';
            }
          }
        } else {
          echo '<p><em>No transcript turns recorded.</em></p>';
        }
        echo '</div>';
      }
    break;

    case 'cloud':
      echo '<h2>Cloud Connections</h2>';
      $reg   = vl_cloud_connectors();
      $conns = vl_conn_store_get();
      $mine  = $conns[$id] ?? [];
      $back  = add_query_arg(['page'=>'vl-client-profile','id'=>$id,'tab'=>'cloud'], admin_url('admin.php'));

      echo '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;">';
      foreach ($reg as $slug=>$meta) {
        $connected = !empty($mine[$slug]['connected']);
        $last_sync = !empty($mine[$slug]['last_sync']) ? human_time_diff((int)$mine[$slug]['last_sync']).' ago' : '—';
        echo '<div class="card" style="border:1px solid #ddd;border-radius:8px;padding:16px;background:#fff;">';
        echo '<h3 style="margin:0 0 8px 0;">'.esc_html($meta['label']).'</h3>';
        echo '<p style="margin:4px 0 10px 0;"><a href="'.esc_url($meta['site']).'" target="_blank" rel="noopener">Visit '.esc_html($meta['label']).'</a></p>';
        echo '<p>Status: '.($connected?'<strong style="color:#057a25">Connected</strong>':'<strong style="color:#a50000">Not Connected</strong>').'</p>';
        echo '<p>Last Sync: '.esc_html($last_sync).'</p>';

        if ($connected) {
          echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" style="display:inline-block;margin-right:8px;">';
          wp_nonce_field('vl_cloud_sync_now');
          echo '<input type="hidden" name="action" value="vl_cloud_sync_now">';
          echo '<input type="hidden" name="lic_id" value="'.esc_attr($id).'">';
          echo '<input type="hidden" name="service" value="'.esc_attr($slug).'">';
          echo '<input type="hidden" name="back" value="'.esc_attr($back).'">';
          echo '<button class="button">Sync Now</button>';
          echo '</form>';

          echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" style="display:inline-block;">';
          wp_nonce_field('vl_cloud_disconnect');
          echo '<input type="hidden" name="action" value="vl_cloud_disconnect">';
          echo '<input type="hidden" name="lic_id" value="'.esc_attr($id).'">';
          echo '<input type="hidden" name="service" value="'.esc_attr($slug).'">';
          echo '<input type="hidden" name="back" value="'.esc_attr($back).'">';
          echo '<button class="button button-secondary" style="margin-left:6px;">Disconnect</button>';
          echo '</form>';
        } else {
          echo '<details style="margin-top:8px;"><summary><strong>Connect</strong></summary>';
          echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" style="margin-top:10px;">';
          wp_nonce_field('vl_cloud_connect');
          echo '<input type="hidden" name="action" value="vl_cloud_connect">';
          echo '<input type="hidden" name="lic_id" value="'.esc_attr($id).'">';
          echo '<input type="hidden" name="service" value="'.esc_attr($slug).'">';
          echo '<input type="hidden" name="back" value="'.esc_attr($back).'">';

          foreach ($meta['fields'] as $f) {
            $name = $f['k']; $label=$f['label']; $type=$f['type']; $ph=$f['placeholder']??'';
            echo '<p style="margin:6px 0;"><label><span style="display:inline-block;width:200px;">'.esc_html($label).'</span>';
            if ($type==='textarea') {
              echo '<textarea name="'.esc_attr($name).'" class="large-text code" rows="4" placeholder="'.esc_attr($ph).'"></textarea>';
            } else {
              $input_type = $type==='password' ? 'password' : 'text';
              echo '<input type="'.$input_type.'" name="'.esc_attr($name).'" class="regular-text code" placeholder="'.esc_attr($ph).'" />';
            }
            echo '</label></p>';
          }
          echo '<p><button class="button button-primary">Connect</button></p>';
          echo '</form></details>';
        }

        echo '</div>';
      }
      echo '</div>';
      break;

    case 'overview':
    default:
      $site_info = (array)($data['site'] ?? []);
      $wp        = (array)($data['wordpress'] ?? []);
      echo '<h2>Overview</h2>';
      echo '<table class="widefat striped" style="max-width:800px;"><tbody>';
      echo '<tr><th style="width:220px;">Status</th><td>'.vl_status_pill_from_row($row).'</td></tr>';
      echo '<tr><th>Home URL</th><td>'.(!empty($site_info['home_url'])?esc_html($site_info['home_url']):'—').'</td></tr>';
      echo '<tr><th>HTTPS</th><td>'.(!empty($site_info['https'])?'Yes':'No').'</td></tr>';
      if (!empty($wp['version'])) echo '<tr><th>WordPress Version</th><td>'.esc_html($wp['version']).'</td></tr>';
      if (!empty($wp['theme']['name'])) echo '<tr><th>Active Theme</th><td>'.esc_html($wp['theme']['name'].' '.$wp['theme']['version']).'</td></tr>';
      echo '</tbody></table>';
      break;
  }

  echo '</div>';
}

/* =======================================================================
 * Cloud connectors registry
 * ===================================================================== */
function vl_cloud_connectors(): array {
  return [
    'aws' => [
      'label' => 'Amazon Web Services',
      'site'  => 'https://aws.amazon.com/',
      'fields'=> [
        ['k'=>'access_key','label'=>'Access Key ID','type'=>'text','placeholder'=>'AKIA...'],
        ['k'=>'secret_key','label'=>'Secret Access Key','type'=>'password','placeholder'=>'••••••••'],
      ],
    ],
    'azure' => [
      'label' => 'Microsoft Azure',
      'site'  => 'https://azure.microsoft.com/',
      'fields'=> [
        ['k'=>'tenant_id','label'=>'Tenant ID','type'=>'text','placeholder'=>'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'],
        ['k'=>'client_id','label'=>'Client ID','type'=>'text','placeholder'=>'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'],
        ['k'=>'client_secret','label'=>'Client Secret','type'=>'password','placeholder'=>'••••••••'],
      ],
    ],
    'openai' => [
      'label' => 'OpenAI',
      'site'  => 'https://platform.openai.com/',
      'fields'=> [
        ['k'=>'api_key','label'=>'API Key','type'=>'password','placeholder'=>'sk-...'],
        ['k'=>'organization','label'=>'Organization (optional)','type'=>'text','placeholder'=>'org_...'],
        ['k'=>'project','label'=>'Project (optional)','type'=>'text','placeholder'=>'proj_...'],
      ],
    ],
    'ahrefs' => [
      'label' => 'Ahrefs',
      'site'  => 'https://ahrefs.com/',
      'fields'=> [
        ['k'=>'token','label'=>'API Token','type'=>'password','placeholder'=>'ahrefs_...'],
      ],
    ],
    'gcp' => [
      'label' => 'Google Cloud',
      'site'  => 'https://cloud.google.com/',
      'fields'=> [
        ['k'=>'service_account_json','label'=>'Service Account JSON','type'=>'textarea','placeholder'=>'{ "type": "service_account", ... }'],
      ],
    ],
  ];
}

/* =======================================================================
 * Cloud connect/disconnect/sync handlers
 * ===================================================================== */
add_action('admin_post_vl_cloud_connect', function () {
  if (!current_user_can('manage_options')) wp_die('Forbidden');
  check_admin_referer('vl_cloud_connect');

  $lic_id = sanitize_text_field($_POST['lic_id'] ?? '');
  $svc    = sanitize_key($_POST['service'] ?? '');
  $back   = esc_url_raw($_POST['back'] ?? admin_url('admin.php?page=vl-licenses'));

  if (!$lic_id || !$svc) { wp_redirect($back); exit; }

  $reg = vl_cloud_connectors();
  if (!isset($reg[$svc])) { wp_redirect($back); exit; }

  $conns = vl_conn_store_get();
  if (!isset($conns[$lic_id])) $conns[$lic_id] = [];

  $payload = [
    'connected' => true,
       'saved_at'  => time(),
    'last_sync' => 0,
    'data'      => [],
  ];
  foreach ($reg[$svc]['fields'] as $f) {
    $key = $f['k'];
    $val = $_POST[$key] ?? '';
    if (is_string($val)) $val = trim($val);
    if ($f['type'] === 'textarea') {
      $payload['data'][$key] = wp_kses_post($val);
    } else {
      $payload['data'][$key] = sanitize_text_field($val);
    }
  }
  $conns[$lic_id][$svc] = $payload;
  vl_conn_store_set($conns);

  wp_redirect($back);
  exit;
});

add_action('admin_post_vl_cloud_disconnect', function () {
  if (!current_user_can('manage_options')) wp_die('Forbidden');
  check_admin_referer('vl_cloud_disconnect');

  $lic_id = sanitize_text_field($_POST['lic_id'] ?? '');
  $svc    = sanitize_key($_POST['service'] ?? '');
  $back   = esc_url_raw($_POST['back'] ?? admin_url('admin.php?page=vl-licenses'));
  if (!$lic_id || !$svc) { wp_redirect($back); exit; }

  $conns = vl_conn_store_get();
  if (isset($conns[$lic_id][$svc])) {
    unset($conns[$lic_id][$svc]);
    vl_conn_store_set($conns);
  }
  wp_redirect($back);
  exit;
});

add_action('admin_post_vl_cloud_sync_now', function () {
  if (!current_user_can('manage_options')) wp_die('Forbidden');
  check_admin_referer('vl_cloud_sync_now');

  $lic_id = sanitize_text_field($_POST['lic_id'] ?? '');
  $svc    = sanitize_key($_POST['service'] ?? '');
  $back   = esc_url_raw($_POST['back'] ?? admin_url('admin.php?page=vl-licenses'));

  if (!$lic_id || !$svc) { wp_redirect($back); exit; }

  $conns = vl_conn_store_get();
  if (isset($conns[$lic_id][$svc])) {
    // (Stub) Real implementation: call the provider API using stored creds.
    $conns[$lic_id][$svc]['last_sync'] = time();
    vl_conn_store_set($conns);
  }

  wp_redirect($back);
  exit;
});

/* =======================================================================
 * Client Widget Data Enhancement
 * ===================================================================== */

/**
 * Update Hub profile with basic WordPress data from client site
 */
function vl_update_hub_profile_basic_data(string $license_id, string $site_url, string $license_key): void {
  if (!$site_url) return;
  
  // Fetch basic WordPress data from client site
  $headers = ['X-Luna-License' => $license_key];
  $response = wp_remote_get($site_url . '/wp-json/luna_widget/v1/system/site', [
    'timeout' => 10,
    'headers' => $headers
  ]);
  
  if (is_wp_error($response)) {
    error_log('[Luna Hub] Failed to fetch basic data from client: ' . $response->get_error_message());
    return;
  }
  
  $code = wp_remote_retrieve_response_code($response);
  if ($code < 200 || $code >= 300) {
    error_log('[Luna Hub] Client returned HTTP ' . $code . ' for basic data');
    return;
  }
  
  $client_data = json_decode(wp_remote_retrieve_body($response), true);
  if (!is_array($client_data)) {
    error_log('[Luna Hub] Invalid JSON from client for basic data');
    return;
  }
  
  // Update Hub profile with basic WordPress data
  $all_profiles = get_option('vl_hub_profiles', []);
  if (!is_array($all_profiles)) $all_profiles = [];
  
  if (!isset($all_profiles[$license_id])) {
    $all_profiles[$license_id] = [];
  }
  
  // Store basic WordPress data
  $all_profiles[$license_id]['site'] = $site_url;
  $all_profiles[$license_id]['license_key'] = $license_key;
  $all_profiles[$license_id]['wp_version'] = $client_data['wordpress']['version'] ?? '';
  $all_profiles[$license_id]['theme'] = [
    'name' => $client_data['wordpress']['theme']['name'] ?? '',
    'version' => $client_data['wordpress']['theme']['version'] ?? '',
    'is_active' => !empty($client_data['wordpress']['theme']['is_active'])
  ];
  $all_profiles[$license_id]['plugins'] = $client_data['plugins'] ?? [];
  $all_profiles[$license_id]['themes'] = $client_data['themes'] ?? []; // Store full themes array with updates
  $all_profiles[$license_id]['users'] = []; // Would need separate endpoint for users
  $all_profiles[$license_id]['updated_at'] = current_time('mysql');
  
  update_option('vl_hub_profiles', $all_profiles);
  
  error_log('[Luna Hub] Updated profile with basic WordPress data for license: ' . $license_id);
}

/**
 * Fetch comprehensive client data from Hub for widget responses
 * This allows the client widget to access all Hub-stored profile data
 */
function vl_fetch_hub_data_for_widget(string $license_key): array {
  // Get all stored profiles
  $all_profiles = get_option('vl_hub_profiles', []);
  if (!is_array($all_profiles)) $all_profiles = [];
  
  // Find profile by license key (try both formats)
  $profile = null;
  foreach ($all_profiles as $profile_id => $profile_data) {
    if (isset($profile_data['license_key']) && $profile_data['license_key'] === $license_key) {
      $profile = $profile_data;
      break;
    }
    // Also check if the profile_id itself is the license key
    if ($profile_id === $license_key) {
      $profile = $profile_data;
      break;
    }
  }
  
  return $profile ?: [];
}

/**
 * Enhanced system data endpoint for client widgets
 * This provides comprehensive data that the widget can use for responses
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/system/comprehensive', [
    'methods' => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function ($req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      // First, find the license ID from the license key
      $store = vl_lic_store_get();
      $license_id = null;
      foreach ($store as $id => $row) {
        if (!empty($row['key']) && hash_equals($row['key'], $license)) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'Invalid license key'], 403);
      }
      
      // Get stored client profile data from Hub using the license ID
      $all_profiles = get_option('vl_hub_profiles', []);
      if (!is_array($all_profiles)) $all_profiles = [];
      
      // Find the client profile by license ID
      $client_profile = $all_profiles[$license_id] ?? null;
      
      if (!$client_profile) {
        return new WP_REST_Response([
          'error' => 'Client profile not found',
          'debug' => [
            'license_key' => $license,
            'license_id' => $license_id,
            'available_profiles' => array_keys($all_profiles),
            'profile_count' => count($all_profiles)
          ]
        ], 404);
      }
      
      // Build response from stored client profile data
      $site_data = [
        'home_url' => $client_profile['site'] ?? '',
        'https' => !empty($client_profile['https']),
        'wordpress' => [
          'version' => $client_profile['wp_version'] ?? '',
          'theme' => [
            'name' => $client_profile['theme']['name'] ?? '',
            'version' => $client_profile['theme']['version'] ?? '',
            'is_active' => !empty($client_profile['theme']['is_active'])
          ]
        ],
        'plugins' => $client_profile['plugins'] ?? [],
        'themes' => $client_profile['themes'] ?? [],
        'users' => $client_profile['users'] ?? [],
        'security' => $client_profile['security'] ?? []
      ];
      
      // Fetch additional data from client site if not in profile
      if (empty($client_profile['_posts']) || empty($client_profile['_pages'])) {
        $additional_data = vl_fetch_client_all($client_profile['site'] ?? '', $license);
        
        // Add posts data
        if (!empty($additional_data['_posts'])) {
          $site_data['_posts'] = $additional_data['_posts'];
        }
        
        // Add pages data  
        if (!empty($additional_data['_pages'])) {
          $site_data['_pages'] = $additional_data['_pages'];
        }
        
        // Add themes data
        if (!empty($additional_data['themes'])) {
          $site_data['themes'] = $additional_data['themes'];
        }
        
        // Add users data if missing
        if (!empty($additional_data['_users']) && empty($site_data['users'])) {
          $site_data['users'] = $additional_data['_users']['items'] ?? [];
        }
      } else {
        // Use cached data from profile
        if (!empty($client_profile['_posts'])) {
          $site_data['_posts'] = $client_profile['_posts'];
        }
        if (!empty($client_profile['_pages'])) {
          $site_data['_pages'] = $client_profile['_pages'];
        }
        if (!empty($client_profile['themes'])) {
          $site_data['themes'] = $client_profile['themes'];
        }
      }
      
      return new WP_REST_Response($site_data, 200);
    }
  ]);
});

/**
 * Enhanced conversation logging endpoint
 * This allows client widgets to log conversations back to the Hub
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/conversations/log', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function ($req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        // error_log('[Luna Hub] Conversation log: No license provided');
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $conversation_data = $req->get_json_params();
      if (!$conversation_data) {
        // error_log('[Luna Hub] Conversation log: Invalid conversation data');
        return new WP_REST_Response(['error' => 'Invalid conversation data'], 400);
      }
      
      // error_log('[Luna Hub] Conversation log: Received conversation from license: ' . substr($license, 0, 8) . '...');
      // error_log('[Luna Hub] Conversation log: Data: ' . print_r($conversation_data, true));
      
      // Store conversation in Hub
      $conversations = get_option('vl_hub_conversations', []);
      if (!is_array($conversations)) $conversations = [];
      
      $conversation_id = $conversation_data['id'] ?? uniqid('conv_');
      $conversations[$conversation_id] = [
        'license' => $license,
        'site' => home_url(),
        'started_at' => $conversation_data['started_at'] ?? current_time('mysql'),
        'transcript' => $conversation_data['transcript'] ?? [],
        'logged_at' => current_time('mysql'),
      ];
      
      update_option('vl_hub_conversations', $conversations);
      
      // error_log('[Luna Hub] Conversation log: Stored conversation with ID: ' . $conversation_id);
      
      return new WP_REST_Response(['ok' => true, 'id' => $conversation_id], 200);
    }
  ]);
});

/**
 * Security data endpoint for client widgets
 * This allows client widgets to send security data to the Hub
 */
add_action('rest_api_init', function () {
  register_rest_route('vl-hub/v1', '/profile/security', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function ($req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      // Find the license ID from the license key
      $store = vl_lic_store_get();
      $license_id = null;
      foreach ($store as $id => $row) {
        if (!empty($row['key']) && hash_equals($row['key'], $license)) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'Invalid license key'], 403);
      }
      
      $security_data = $req->get_json_params();
      if (!$security_data) {
        return new WP_REST_Response(['error' => 'Invalid security data'], 400);
      }
      
      // Store security data in Hub profiles
      $all_profiles = get_option('vl_hub_profiles', []);
      if (!is_array($all_profiles)) $all_profiles = [];
      
      // Initialize profile if it doesn't exist
      if (!isset($all_profiles[$license_id])) {
        $all_profiles[$license_id] = [];
      }
      
      // Update security data
      $all_profiles[$license_id]['security'] = $security_data;
      $all_profiles[$license_id]['license_key'] = $license;
      $all_profiles[$license_id]['site'] = $req->get_header('X-Luna-Site') ?: home_url();
      $all_profiles[$license_id]['updated_at'] = current_time('mysql');
      
      update_option('vl_hub_profiles', $all_profiles);
      
      return new WP_REST_Response(['ok' => true, 'message' => 'Security data saved'], 200);
    }
  ]);
});

/**
 * Test endpoint to verify license key and Hub functionality
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/test', [
    'methods' => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function ($req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      
      return new WP_REST_Response([
        'ok' => true,
        'license_provided' => !empty($license),
        'license_key' => $license ? substr($license, 0, 8) . '...' : 'NOT PROVIDED',
        'hub_url' => home_url(),
        'timestamp' => current_time('mysql'),
        'message' => 'Hub is working!'
      ], 200);
    }
  ]);
});

/**
 * Force refresh endpoint to update Hub profile data
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/force-refresh', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function ($req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (empty($license)) {
        return new WP_REST_Response(['error' => 'License key required'], 400);
      }

      // Find license ID
      $licenses = vl_lic_store_get();
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if (isset($lic['key']) && $lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }

      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }

      // Force update the profile
      $license_data = $licenses[$license_id];
      $result = vl_update_hub_profile_basic_data($license_id, $license_data['site'] ?? '', $license);
      
      return new WP_REST_Response([
        'success' => true,
        'license_id' => $license_id,
        'updated' => $result,
        'message' => 'Profile data refreshed successfully'
      ], 200);
    }
  ]);
});

/**
 * Keywords sync endpoint for client widgets
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/keywords/sync', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function ($req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (empty($license)) {
        return new WP_REST_Response(['error' => 'License key required'], 400);
      }

      // Find license ID
      $licenses = vl_lic_store_get();
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if (isset($lic['key']) && $lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }

      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }

      // Store keywords in Hub profile
      $keywords = $req->get_json_params()['keywords'] ?? [];
      if (!empty($keywords)) {
        $all_profiles = get_option('vl_hub_profiles', []);
        if (!is_array($all_profiles)) $all_profiles = [];
        
        if (!isset($all_profiles[$license_id])) {
          $all_profiles[$license_id] = [];
        }
        
        $all_profiles[$license_id]['keywords'] = $keywords;
        $all_profiles[$license_id]['keywords_updated_at'] = current_time('mysql');
        
        update_option('vl_hub_profiles', $all_profiles);
      }
      
      return new WP_REST_Response([
        'success' => true,
        'license_id' => $license_id,
        'keywords_synced' => count($keywords),
        'message' => 'Keywords synced successfully'
      ], 200);
    }
  ]);
});

/**
 * Create WordPress users for VL clients
 */
function vl_create_client_users() {
    $licenses = get_option('vl_licenses_registry', array());
    $created_users = array();
    $errors = array();
    
    if (!empty($licenses) && is_array($licenses)) {
        foreach ($licenses as $license_key => $license_data) {
            if (isset($license_data['client_name']) && isset($license_data['status']) && $license_data['status'] === 'active') {
                $client_name = sanitize_text_field($license_data['client_name']);
                $username = sanitize_user(strtolower(str_replace(' ', '_', $client_name)));
                $email = isset($license_data['email']) ? sanitize_email($license_data['email']) : $username . '@visiblelight.ai';
                
                // Check if user already exists
                $existing_user = get_user_by('login', $username);
                if (!$existing_user) {
                    // Create new user
                    $user_id = wp_create_user($username, wp_generate_password(), $email);
                    
                    if (!is_wp_error($user_id)) {
                        // Set user role to 'subscriber' (read-only access)
                        $user = new WP_User($user_id);
                        $user->set_role('subscriber');
                        
                        // Add custom meta for license key
                        update_user_meta($user_id, 'vl_license_key', $license_key);
                        update_user_meta($user_id, 'vl_client_name', $client_name);
                        
                        $created_users[] = array(
                            'user_id' => $user_id,
                            'username' => $username,
                            'client_name' => $client_name,
                            'email' => $email,
                            'license_key' => $license_key
                        );
                    } else {
                        $errors[] = array(
                            'client_name' => $client_name,
                            'error' => $user_id->get_error_message()
                        );
                    }
                } else {
                    // Update existing user's license key
                    update_user_meta($existing_user->ID, 'vl_license_key', $license_key);
                    update_user_meta($existing_user->ID, 'vl_client_name', $client_name);
                }
            }
        }
    }
    
    return array(
        'created_users' => $created_users,
        'errors' => $errors,
        'total_processed' => count($licenses)
    );
}

/**
 * Add admin menu for client user management
 */
add_action('admin_menu', function() {
    add_submenu_page(
        'vl-clients',
        'Client Users',
        'Client Users',
        'manage_options',
        'vl-client-users',
        'vl_client_users_page'
    );
}, 25);

function vl_client_users_page() {
    if (isset($_POST['create_users']) && wp_verify_nonce($_POST['_wpnonce'], 'vl_create_users')) {
        $result = vl_create_client_users();
        echo '<div class="notice notice-success"><p>Created ' . count($result['created_users']) . ' client users successfully!</p></div>';
        if (!empty($result['errors'])) {
            echo '<div class="notice notice-warning"><p>Errors: ' . count($result['errors']) . '</p></div>';
        }
    }
    
    $result = vl_create_client_users();
    $users = get_users(array('meta_key' => 'vl_license_key'));
    
    echo '<div class="wrap">';
    echo '<h1>VL Client Users</h1>';
    echo '<p>Manage WordPress users for Visible Light clients.</p>';
    
    echo '<form method="post" style="margin-bottom: 20px;">';
    wp_nonce_field('vl_create_users');
    echo '<input type="submit" name="create_users" class="button button-primary" value="Create/Update Client Users">';
    echo '</form>';
    
    echo '<h2>Current Client Users (' . count($users) . ')</h2>';
    echo '<table class="wp-list-table widefat fixed striped">';
    echo '<thead><tr><th>Username</th><th>Client Name</th><th>Email</th><th>License Key</th><th>Role</th></tr></thead>';
    echo '<tbody>';
    
    foreach ($users as $user) {
        $license_key = get_user_meta($user->ID, 'vl_license_key', true);
        $client_name = get_user_meta($user->ID, 'vl_client_name', true);
        echo '<tr>';
        echo '<td>' . esc_html($user->user_login) . '</td>';
        echo '<td>' . esc_html($client_name) . '</td>';
        echo '<td>' . esc_html($user->user_email) . '</td>';
        echo '<td>' . esc_html($license_key) . '</td>';
        echo '<td>' . esc_html(implode(', ', $user->roles)) . '</td>';
        echo '</tr>';
    }
    
    echo '</tbody></table>';
    echo '</div>';
}

add_filter('login_redirect', function ($redirect_to, $requested_redirect_to, $user) {
  if ($user instanceof WP_User) {
    $license_key = trim((string) get_user_meta($user->ID, 'vl_license_key', true));
    if ($license_key !== '') {
      $license = vl_lic_lookup_by_key($license_key);
      if ($license && empty($license['active'])) {
        return $redirect_to ?: home_url('/ai-constellation-console/');
      }

      return vl_lic_dashboard_url($license, $license_key);
    }
  }

  return $redirect_to ?: home_url('/ai-constellation-console/');
}, 10, 3);

/* =======================================================================
 * Temporary Test Function
 * ===================================================================== */
add_action('admin_menu', function() {
    add_submenu_page(
        'vl-clients',
        'TEST Client Users',
        'TEST Client Users',
        'manage_options',
        'vl-test-client-users',
        function() {
            echo '<div class="wrap"><h1>TEST: Client Users Page</h1><p>If you can see this, the plugin is working!</p></div>';
        }
    );
}, 30);

/* =======================================================================
 * Done
 * ===================================================================== */