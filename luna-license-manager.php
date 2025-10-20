<?php
/**
 * Plugin Name: Luna License Manager (Clean)
 * Description: Manages Luna Licenses and VL Client Users - Clean version without conflicting REST API endpoints
 * Version: 1.0.0
 * Author: Visible Light
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/* =======================================================================
 * Plugin Activation/Deactivation
 * ===================================================================== */

register_activation_hook(__FILE__, 'vl_activate_license_manager');
register_deactivation_hook(__FILE__, 'vl_deactivate_license_manager');

function vl_activate_license_manager() {
    // Add custom VL Client role
    vl_add_clients_role();

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
    if (empty($licenses)) {
        $default_licenses = array(
            'lic_3d2c5795-b6c2-482f-8cb9-cf36603768e8' => array(
                'client_name' => 'Commonwealth Health Services',
                'status'      => 'active',
                'created'     => current_time('mysql'),
            ),
            'lic_68712354-ee80-4eb9-94d7-1a1f6404bb80' => array(
                'client_name' => 'Site Assembly',
                'status'      => 'active',
                'created'     => current_time('mysql'),
            ),
            'lic_ce0a7680-26eb-484b-ac1a-bb075d944322' => array(
                'client_name' => 'Visible Light',
                'status'      => 'active',
                'created'     => current_time('mysql'),
            ),
        );
        update_option('vl_licenses_registry', $default_licenses);
    }
}

function vl_deactivate_license_manager() {
    // Remove custom VL Client role
    vl_remove_clients_role();
}

/* =======================================================================
 * Custom User Roles
 * ===================================================================== */

function vl_add_clients_role() {
    add_role(
        'vl_client',
        'VL Client',
        array(
            'read'                   => true,
            'vl_access_supercluster' => true,
            'vl_view_own_data'       => true,
        )
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
        'vl_licenses_screen',
        'dashicons-admin-users',
        30
    );

    add_submenu_page(
        'vl-clients',
        'Luna Licenses',
        'Luna Licenses',
        'manage_options',
        'vl-licenses',
        'vl_licenses_screen'
    );

    add_submenu_page(
        'vl-clients',
        'Client Users',
        'Client Users',
        'manage_options',
        'vl-client-users',
        'vl_client_users_screen'
    );
}

/* =======================================================================
 * License Management Functions
 * ===================================================================== */

function vl_lic_store_get() {
    $store = get_option('vl_licenses_registry', array());
    return is_array($store) ? $store : array();
}

function vl_lic_store_set($list) {
    update_option('vl_licenses_registry', $list);
}

function vl_conn_store_get() {
    $store = get_option('vl_connections_registry', array());
    return is_array($store) ? $store : array();
}

function vl_conn_store_set($list) {
    update_option('vl_connections_registry', $list);
}

function vl_lic_generate_key() {
    return 'lic_' . wp_generate_uuid4();
}

function vl_lic_create($client, $site) {
    $key = vl_lic_generate_key();
    return vl_lic_create_with_key($client, $site, $key);
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

function vl_lic_create_with_key($client, $site, $key, $active = true) {
    $license = array(
        'client_name' => $client,
        'site'        => $site,
        'key'         => $key,
        'status'      => $active ? 'active' : 'inactive',
        'created'     => current_time('mysql'),
        'last_seen'   => null,
    );

    $store         = vl_lic_store_get();
    $store[$key]   = $license;
    vl_lic_store_set($store);

    return $license;
}

function vl_lic_redact($key) {
    return substr($key, 0, 8) . '...' . substr($key, -4);
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

function vl_lic_lookup_by_key($key) {
    $store = vl_lic_store_get();
    return isset($store[$key]) ? $store[$key] : null;
}

function vl_lic_dashboard_segment($license_key) {
    $sanitized = preg_replace('/[^A-Za-z0-9\-]/', '-', $license_key);
    $sanitized = trim($sanitized, '-');
    return strtolower($sanitized);
}

function vl_lic_dashboard_url($license, $license_key = '') {
    $key = isset($license['key']) ? $license['key'] : $license_key;
    if (empty($key)) {
        return home_url('/ai-constellation-console/');
    }

    $segment = vl_lic_dashboard_segment($key);
    return home_url('/ai-constellation-console/' . $segment . '/');
}

function vl_status_pill_from_row($row) {
    $status = isset($row['status']) ? $row['status'] : 'unknown';
    $class  = $status === 'active' ? 'vl-status-active' : 'vl-status-inactive';
    return '<span class="vl-status-pill ' . esc_attr($class) . '">' . esc_html(ucfirst($status)) . '</span>';
}

/* =======================================================================
 * Admin Screens
 * ===================================================================== */

function vl_licenses_screen() {
    $licenses    = vl_lic_store_get();
    $connections = vl_conn_store_get();

    if (isset($_POST['action'])) {
        if ($_POST['action'] === 'create_license') {
            check_admin_referer('vl_create_license');

            $client = sanitize_text_field(wp_unslash($_POST['client_name']));
            $site   = sanitize_text_field(wp_unslash($_POST['site']));

            if ($client && $site) {
                vl_lic_create($client, $site);
                echo '<div class="notice notice-success"><p>License created successfully!</p></div>';
            }
        }

        if ($_POST['action'] === 'delete_license') {
            check_admin_referer('vl_delete_license');

            $key = sanitize_text_field(wp_unslash($_POST['license_key']));
            if ($key) {
                $store = vl_lic_store_get();
                unset($store[$key]);
                vl_lic_store_set($store);
                echo '<div class="notice notice-success"><p>License deleted successfully!</p></div>';
            }
        }
    }
    ?>
    <div class="wrap">
        <h1>Luna Licenses</h1>

        <div class="vl-admin-grid">
            <div class="vl-admin-card">
                <h2>Create New License</h2>
                <form method="post">
                    <?php wp_nonce_field('vl_create_license'); ?>
                    <input type="hidden" name="action" value="create_license">
                    <table class="form-table">
                        <tr>
                            <th scope="row">Client Name</th>
                            <td><input type="text" name="client_name" required class="regular-text"></td>
                        </tr>
                        <tr>
                            <th scope="row">Site</th>
                            <td><input type="text" name="site" required class="regular-text"></td>
                        </tr>
                    </table>
                    <?php submit_button('Create License'); ?>
                </form>
            </div>

            <div class="vl-admin-card">
                <h2>Existing Licenses</h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Client</th>
                            <th>Site</th>
                            <th>Key</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($licenses as $license) : ?>
                            <tr>
                                <td><?php echo esc_html($license['client_name']); ?></td>
                                <td><?php echo esc_html($license['site']); ?></td>
                                <td><code><?php echo esc_html(vl_lic_redact($license['key'])); ?></code></td>
                                <td><?php echo vl_status_pill_from_row($license); ?></td>
                                <td><?php echo esc_html($license['created']); ?></td>
                                <td>
                                    <a href="<?php echo esc_url(vl_lic_dashboard_url($license)); ?>" class="button button-small">View Dashboard</a>
                                    <form method="post" style="display:inline;">
                                        <?php wp_nonce_field('vl_delete_license'); ?>
                                        <input type="hidden" name="action" value="delete_license">
                                        <input type="hidden" name="license_key" value="<?php echo esc_attr($license['key']); ?>">
                                        <input type="submit" class="button button-small" value="Delete" onclick="return confirm('Are you sure?');">
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <style>
    .vl-admin-grid {
        display: grid;
        grid-template-columns: 1fr 2fr;
        gap: 20px;
        margin-top: 20px;
    }
    .vl-admin-card {
        background: #fff;
        border: 1px solid #ccd0d4;
        border-radius: 4px;
        padding: 20px;
    }
    .vl-status-pill {
        padding: 4px 8px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
    }
    .vl-status-active {
        background: #d4edda;
        color: #155724;
    }
    .vl-status-inactive {
        background: #f8d7da;
        color: #721c24;
    }
    </style>
    <?php
}

function vl_client_users_screen() {
    if (isset($_POST['action']) && $_POST['action'] === 'create_client_users') {
        check_admin_referer('vl_create_client_users');
        vl_create_client_users();
    }

    $vl_users  = get_users(array('role' => 'vl_client'));
    $licenses  = vl_lic_store_get();
    ?>
    <div class="wrap">
        <h1>VL Client Users</h1>

        <div class="vl-admin-grid">
            <div class="vl-admin-card">
                <h2>Create/Update Client Users</h2>
                <p>This will create WordPress users for each active license holder.</p>
                <form method="post">
                    <?php wp_nonce_field('vl_create_client_users'); ?>
                    <input type="hidden" name="action" value="create_client_users">
                    <?php submit_button('Create/Update Client Users', 'primary', 'submit', false); ?>
                </form>
            </div>

            <div class="vl-admin-card">
                <h2>Current VL Client Users</h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Email</th>
                            <th>License Key</th>
                            <th>Client Name</th>
                            <th>Role</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($vl_users as $user) : ?>
                            <tr>
                                <td><?php echo esc_html($user->user_login); ?></td>
                                <td><?php echo esc_html($user->user_email); ?></td>
                                <td><code><?php echo esc_html(vl_lic_redact(get_user_meta($user->ID, 'vl_license_key', true))); ?></code></td>
                                <td><?php echo esc_html(get_user_meta($user->ID, 'vl_client_name', true)); ?></td>
                                <td><?php echo esc_html(implode(', ', $user->roles)); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <?php
}

/* =======================================================================
 * Client User Creation
 * ===================================================================== */

function vl_create_client_users() {
    $licenses      = vl_lic_store_get();
    $created_count = 0;

    // Map license keys to client names
    $client_mapping = array(
        'lic_3d2c5795-b6c2-482f-8cb9-cf36603768e8' => 'Commonwealth Health Services',
        'lic_68712354-ee80-4eb9-94d7-1a1f6404bb80' => 'Site Assembly',
        'lic_ce0a7680-26eb-484b-ac1a-bb075d944322' => 'Visible Light',
    );

    foreach ($licenses as $license_key => $license_data) {
        $client_name = isset($client_mapping[$license_key]) ?
            $client_mapping[$license_key] :
            (isset($license_data['client_name']) ? $license_data['client_name'] : 'Unknown Client');

        $username = strtolower(str_replace(' ', '_', $client_name));
        $email    = $username . '@visiblelight.ai';

        $existing_user = get_user_by('login', $username);

        if ($existing_user) {
            wp_update_user(
                array(
                    'ID'         => $existing_user->ID,
                    'user_email' => $email,
                    'role'       => 'vl_client',
                )
            );

            update_user_meta($existing_user->ID, 'vl_license_key', $license_key);
            update_user_meta($existing_user->ID, 'vl_client_name', $client_name);

            $created_count++;
        } else {
            $user_id = wp_create_user($username, wp_generate_password(12, true), $email);

            if (!is_wp_error($user_id)) {
                $user = new WP_User($user_id);
                $user->set_role('vl_client');

                update_user_meta($user_id, 'vl_license_key', $license_key);
                update_user_meta($user_id, 'vl_client_name', $client_name);

                $created_count++;
            }
        }
    }

    if ($created_count > 0) {
        echo '<div class="notice notice-success"><p>Created or updated ' . intval($created_count) . ' client users.</p></div>';
    } else {
        echo '<div class="notice notice-warning"><p>No client users were created. Check your license registry.</p></div>';
    }
}

/* =======================================================================
 * Login Redirects
 * ===================================================================== */

add_filter('login_redirect', 'vl_handle_login_redirect', 10, 3);

function vl_handle_login_redirect($redirect_to, $requested_redirect_to, $user) {
    if (!($user instanceof WP_User)) {
        return $redirect_to;
    }

    if (in_array('vl_client', $user->roles, true)) {
        $license_key = get_user_meta($user->ID, 'vl_license_key', true);
        $license     = $license_key ? vl_lic_lookup_by_key($license_key) : null;

        if ($license_key && $license && (isset($license['status']) ? $license['status'] === 'active' : true)) {
            return vl_lic_dashboard_url($license, $license_key);
        }

        return home_url('/ai-constellation-console/');
    }

    // Allow WordPress to handle admin redirects normally
    if (!empty($requested_redirect_to)) {
        return $requested_redirect_to;
    }

    return $redirect_to;
}

// Handle logout redirects
add_action('wp_logout', 'vl_handle_logout_redirect');

function vl_handle_logout_redirect() {
    wp_safe_redirect(home_url('/supercluster-login/'));
    exit;
}

/* =======================================================================
 * Template Redirects
 * ===================================================================== */

add_action('template_redirect', 'vl_protect_console');

function vl_protect_console() {
    if (is_page('ai-constellation-console') && !is_user_logged_in()) {
        wp_safe_redirect(home_url('/supercluster-login/'));
        exit;
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
}

add_action('template_redirect', 'vl_redirect_authenticated_clients');

function vl_redirect_authenticated_clients() {
    if (is_page('supercluster-login') && is_user_logged_in()) {
        $user = wp_get_current_user();
        if (in_array('vl_client', (array) $user->roles, true)) {
            $license_key = get_user_meta($user->ID, 'vl_license_key', true);
            $license     = $license_key ? vl_lic_lookup_by_key($license_key) : null;
            $url         = $license ? vl_lic_dashboard_url($license, $license_key) : home_url('/ai-constellation-console/');
            wp_safe_redirect($url);
            exit;
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
}

/* =======================================================================
 * REST API endpoints (client-initiated activate/heartbeat)
 * ===================================================================== */

add_action('rest_api_init', 'vl_register_license_routes');

function vl_register_license_routes() {
    register_rest_route(
        'vl-license/v1',
        '/activate',
        array(
            'methods'             => 'POST',
            'permission_callback' => '__return_true',
            'callback'            => 'vl_rest_activate_license',
        )
    );

    register_rest_route(
        'vl-license/v1',
        '/heartbeat',
        array(
            'methods'             => 'POST',
            'permission_callback' => '__return_true',
            'callback'            => 'vl_rest_license_heartbeat',
        )
    );
}

function vl_rest_activate_license($request) {
    $license = trim((string) $request->get_param('license'));
    $site    = esc_url_raw((string) $request->get_param('site_url'));
    $name    = sanitize_text_field((string) $request->get_param('site_name'));
    $wpv     = sanitize_text_field((string) $request->get_param('wp_version'));
    $pv      = sanitize_text_field((string) $request->get_param('plugin_version'));

    if (!$license || !$site) {
        return new WP_REST_Response(array('ok' => false, 'error' => 'missing_params'), 400);
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

    $store    = vl_lic_store_get();
    $found_id = null;

    foreach ($store as $id => $row) {
        if (isset($row['key']) && $row['key'] === $license) {
            $found_id = $id;
            break;
        }
    }

    if (!$found_id) {
        return new WP_REST_Response(array('ok' => false, 'error' => 'license_not_found'), 404);
    }

    $store[$found_id]['last_seen']       = current_time('mysql');
    $store[$found_id]['site']            = $site;
    $store[$found_id]['site_name']       = $name;
    $store[$found_id]['wp_version']      = $wpv;
    $store[$found_id]['plugin_version']  = $pv;
    $store[$found_id]['status']          = 'active';

    vl_lic_store_set($store);

    return new WP_REST_Response(array('ok' => true, 'license' => $found_id), 200);
}

function vl_rest_license_heartbeat($request) {
    $license = trim((string) $request->get_param('license'));
    if (!$license) {
        return new WP_REST_Response(array('ok' => false, 'error' => 'missing_license'), 400);
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

    $store    = vl_lic_store_get();
    $found_id = null;

    foreach ($store as $id => $row) {
        if (isset($row['key']) && $row['key'] === $license) {
            $found_id = $id;
            break;
        }
    }

    if (!$found_id) {
        return new WP_REST_Response(array('ok' => false, 'error' => 'license_not_found'), 404);
    }

    $store[$found_id]['last_seen'] = current_time('mysql');
    vl_lic_store_set($store);

    return new WP_REST_Response(array('ok' => true), 200);
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
 * Done
 * ===================================================================== */

