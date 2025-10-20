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

    // Create default licenses if none exist
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

function vl_remove_clients_role() {
    remove_role('vl_client');
}

/* =======================================================================
 * Admin Menu
 * ===================================================================== */

add_action('admin_menu', 'vl_licenses_admin_menu');

function vl_licenses_admin_menu() {
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

/* =======================================================================
 * Done
 * ===================================================================== */

