<?php
/**
 * Plugin Name: Luna Chat Endpoint Pro v1.1
 * Description: Hub-side REST API endpoints for Luna Chat system. Handles all API requests from client sites.
 * Version:     2.0.0
 * Author:      Visible Light
 * License:     GPLv2 or later
 */

if ( ! defined( 'ABSPATH' ) ) exit;

/* =========================================================================
 * Core Hub Endpoints Only
 * ========================================================================= */

/**
 * Chat endpoint for client sites
 */
add_action('rest_api_init', function () {
  register_rest_route('luna/v1', '/chat-live', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $tenant = $req->get_param('tenant') ?: 'demo';
      $prompt = $req->get_param('prompt') ?: '';
      
      if (empty($prompt)) {
        return new WP_REST_Response(['answer' => 'Please provide a message.'], 400);
      }
      
      // Simple response for Hub
      return new WP_REST_Response([
        'answer' => 'This is a Hub endpoint. Client sites should use their own chat functionality.',
        'sources' => [],
        'actions' => [],
        'confidence' => 0.8,
      ], 200);
    },
  ]);
});

/**
 * Health check endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna/v1', '/health', [
    'methods' => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      return new WP_REST_Response([
        'status' => 'ok',
        'message' => 'Luna Hub endpoints are working',
        'timestamp' => current_time('mysql'),
      ], 200);
    },
  ]);
});

/**
 * Conversations endpoint for client sites to log conversations
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/conversations/log', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $conversation_data = $req->get_json_params();
      if (!$conversation_data) {
        return new WP_REST_Response(['error' => 'Invalid conversation data'], 400);
      }
      
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
      
      return new WP_REST_Response(['ok' => true, 'id' => $conversation_id], 200);
    }
  ]);
});

/**
 * System comprehensive endpoint for client sites (GET to fetch, POST to store)
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/system/comprehensive', [
    'methods' => ['GET', 'POST'],
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Handle POST (store data from client)
      if ($req->get_method() === 'POST') {
        $comprehensive_data = $req->get_json_params();
        if (!$comprehensive_data) {
          return new WP_REST_Response(['error' => 'Invalid comprehensive data'], 400);
        }
        
        // Store comprehensive data in Hub profiles
        $profiles = get_option('vl_hub_profiles', []);
        if (!isset($profiles[$license_id])) {
          $profiles[$license_id] = [];
        }
        
        // Update with comprehensive data
        $profiles[$license_id] = array_merge($profiles[$license_id], $comprehensive_data);
        $profiles[$license_id]['last_updated'] = current_time('mysql');
        
        update_option('vl_hub_profiles', $profiles);
        
        error_log('[Luna Hub] Stored comprehensive data for license_id: ' . $license_id);
        
        return new WP_REST_Response(['ok' => true, 'message' => 'Comprehensive data stored'], 200);
      }
      
      // Handle GET (return data to client)
      $profiles = get_option('vl_hub_profiles', []);
      $client_profile = $profiles[$license_id] ?? null;
      
      if (!$client_profile) {
        return new WP_REST_Response(['error' => 'Client profile not found'], 404);
      }
      
      // Return client's comprehensive data
      return new WP_REST_Response([
        'home_url' => $client_profile['site'] ?? home_url(),
        'https' => !empty($client_profile['https']),
        'wordpress' => [
          'version' => $client_profile['wp_version'] ?? '',
          'theme' => [
            'name' => $client_profile['theme']['name'] ?? '',
            'version' => $client_profile['theme']['version'] ?? '',
            'is_active' => !empty($client_profile['theme']['is_active']),
          ],
        ],
        'plugins' => $client_profile['plugins'] ?? [],
        'themes' => $client_profile['themes'] ?? [],
        'users' => $client_profile['users'] ?? [],
        'security' => $client_profile['security'] ?? [],
        '_posts' => $client_profile['_posts'] ?? [],
        '_pages' => $client_profile['_pages'] ?? [],
        '_users' => $client_profile['_users'] ?? [],
      ], 200);
    }
  ]);
});

/**
 * Security data endpoint for client sites
 */
add_action('rest_api_init', function () {
  register_rest_route('vl-hub/v1', '/profile/security', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $request_data = $req->get_json_params();
      if (!$request_data) {
        return new WP_REST_Response(['error' => 'Invalid security data'], 400);
      }
      
      // Extract security data from the payload
      $security_data = isset($request_data['security']) ? $request_data['security'] : $request_data;
      
      // Debug logging
      error_log('[Luna Hub] Security data received for license: ' . substr($license, 0, 8) . '...');
      error_log('[Luna Hub] Security data: ' . print_r($security_data, true));
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Store security data in Hub profiles
      $profiles = get_option('vl_hub_profiles', []);
      if (!isset($profiles[$license_id])) {
        $profiles[$license_id] = [];
      }
      
      $profiles[$license_id]['security'] = $security_data;
      $profiles[$license_id]['last_updated'] = current_time('mysql');
      
      update_option('vl_hub_profiles', $profiles);
      
      // Debug: Log what was stored
      error_log('[Luna Hub] Stored security data for license_id: ' . $license_id);
      error_log('[Luna Hub] Stored data: ' . print_r($security_data, true));
      
      return new WP_REST_Response(['ok' => true, 'message' => 'Security data stored'], 200);
    }
  ]);
});

/**
 * Session start endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/chat/session-start', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $data = $req->get_json_params();
      if (!$data || !isset($data['session_id'])) {
        return new WP_REST_Response(['error' => 'Session ID required'], 400);
      }
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Store session start data
      $session_starts = get_option('vl_hub_session_starts', []);
      if (!isset($session_starts[$license_id])) {
        $session_starts[$license_id] = [];
      }
      
      $session_starts[$license_id][] = [
        'session_id' => $data['session_id'],
        'started_at' => $data['started_at'] ?? current_time('mysql'),
        'timestamp' => time()
      ];
      
      update_option('vl_hub_session_starts', $session_starts);
      
      error_log('[Luna Hub] Session started for license_id: ' . $license_id . ', session: ' . $data['session_id']);
      
      return new WP_REST_Response(['ok' => true, 'message' => 'Session start recorded'], 200);
    }
  ]);
});

/**
 * Session end endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/chat/session-end', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $data = $req->get_json_params();
      if (!$data || !isset($data['session_id'])) {
        return new WP_REST_Response(['error' => 'Session ID required'], 400);
      }
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Store session end data
      $session_ends = get_option('vl_hub_session_ends', []);
      if (!isset($session_ends[$license_id])) {
        $session_ends[$license_id] = [];
      }
      
      $session_ends[$license_id][] = [
        'session_id' => $data['session_id'],
        'reason' => $data['reason'] ?? 'unknown',
        'ended_at' => $data['ended_at'] ?? current_time('mysql'),
        'timestamp' => time()
      ];
      
      update_option('vl_hub_session_ends', $session_ends);
      
      error_log('[Luna Hub] Session ended for license_id: ' . $license_id . ', session: ' . $data['session_id'] . ', reason: ' . ($data['reason'] ?? 'unknown'));
      
      return new WP_REST_Response(['ok' => true, 'message' => 'Session end recorded'], 200);
    }
  ]);
});

/**
 * Conversation logging endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/conversations/log', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $conversation_data = $req->get_json_params();
      if (!$conversation_data) {
        return new WP_REST_Response(['error' => 'Invalid conversation data'], 400);
      }
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Store conversation data
      $conversations = get_option('vl_hub_conversations', []);
      if (!isset($conversations[$license_id])) {
        $conversations[$license_id] = [];
      }
      
      $conversations[$license_id][] = [
        'id' => $conversation_data['id'] ?? 'conv_' . uniqid('', true),
        'started_at' => $conversation_data['started_at'] ?? current_time('mysql'),
        'transcript' => $conversation_data['transcript'] ?? [],
        'received_at' => current_time('mysql'),
        'timestamp' => time()
      ];
      
      update_option('vl_hub_conversations', $conversations);
      
      error_log('[Luna Hub] Conversation logged for license_id: ' . $license_id . ', conv_id: ' . ($conversation_data['id'] ?? 'unknown'));

      return new WP_REST_Response(['ok' => true, 'message' => 'Conversation logged'], 200);
    }
  ]);
});

/* =========================================================================
 * AI Constellation dataset endpoint
 * ========================================================================= */

add_action('rest_api_init', function () {
  register_rest_route('vl-hub/v1', '/constellation', [
    'methods'  => 'GET',
    'permission_callback' => '__return_true',
    'callback' => 'vl_rest_constellation_dataset',
    'args'     => [
      'license' => [
        'type' => 'string',
        'required' => false,
      ],
    ],
  ]);
});

/**
 * Build a constellation dataset representing Hub + widget telemetry.
 */
function vl_rest_constellation_dataset(WP_REST_Request $req): WP_REST_Response {
  $license_filter = trim((string)$req->get_param('license'));
  $data = vl_constellation_build_dataset($license_filter);
  return new WP_REST_Response($data, 200);
}

/**
 * Assemble constellation data for all licenses or a single filtered license.
 */
function vl_constellation_build_dataset(string $license_filter = ''): array {
  $licenses      = get_option('vl_licenses_registry', []);
  $profiles      = get_option('vl_hub_profiles', []);
  $conversations = get_option('vl_hub_conversations', []);
  $session_starts = get_option('vl_hub_session_starts', []);
  $session_ends   = get_option('vl_hub_session_ends', []);
  $connections    = get_option('vl_client_connections', []);

  $clients = [];
  foreach ($licenses as $license_id => $row) {
    if ($license_filter !== '') {
      $matches = false;
      if (stripos($license_id, $license_filter) !== false) {
        $matches = true;
      } elseif (!empty($row['key']) && stripos((string)$row['key'], $license_filter) !== false) {
        $matches = true;
      } elseif (!empty($row['client']) && stripos((string)$row['client'], $license_filter) !== false) {
        $matches = true;
      }
      if (!$matches) {
        continue;
      }
    }

    $profile   = is_array($profiles[$license_id] ?? null) ? $profiles[$license_id] : [];
    $client_ds = vl_constellation_build_client(
      (string)$license_id,
      is_array($row) ? $row : [],
      $profile,
      is_array($conversations[$license_id] ?? null) ? $conversations[$license_id] : [],
      is_array($session_starts[$license_id] ?? null) ? $session_starts[$license_id] : [],
      is_array($session_ends[$license_id] ?? null) ? $session_ends[$license_id] : [],
      is_array($connections[$license_id] ?? null) ? $connections[$license_id] : []
    );

    $clients[] = $client_ds;
  }

  usort($clients, function ($a, $b) {
    return strcasecmp($a['client'], $b['client']);
  });

  return [
    'generated_at'  => current_time('mysql'),
    'total_clients' => count($clients),
    'clients'       => $clients,
  ];
}

/**
 * Build the constellation node map for an individual client license.
 */
function vl_constellation_build_client(string $license_id, array $license_row, array $profile, array $conversations, array $session_starts, array $session_ends, array $connections): array {
  $palette = [
    'identity'       => '#7ee787',
    'infrastructure' => '#58a6ff',
    'security'       => '#f85149',
    'content'        => '#f2cc60',
    'plugins'        => '#d2a8ff',
    'themes'         => '#8b949e',
    'users'          => '#79c0ff',
    'ai'             => '#bc8cff',
    'sessions'       => '#56d364',
    'integrations'   => '#ffa657',
  ];

  $icons = [
    'identity'       => 'visiblelightailogoonly.svg',
    'infrastructure' => 'arrows-rotate-reverse-regular-full.svg',
    'security'       => 'eye-slash-light-full.svg',
    'content'        => 'play-regular-full.svg',
    'plugins'        => 'plus-solid-full.svg',
    'themes'         => 'visiblelightailogo.svg',
    'users'          => 'eye-regular-full.svg',
    'ai'             => 'visiblelightailogo.svg',
    'sessions'       => 'arrows-rotate-reverse-regular-full.svg',
    'integrations'   => 'minus-solid-full.svg',
  ];

  $client = [
    'license_id'   => $license_id,
    'license_key'  => vl_constellation_redact_key($license_row['key'] ?? ''),
    'client'       => vl_constellation_string($license_row['client'] ?? 'Unassigned Client'),
    'site'         => vl_constellation_string($license_row['site'] ?? ''),
    'active'       => !empty($license_row['active']),
    'created'      => vl_constellation_date($license_row['created'] ?? 0),
    'last_seen'    => vl_constellation_date($license_row['last_seen'] ?? 0),
    'categories'   => [],
  ];

  $client['categories'][] = vl_constellation_identity_category($palette['identity'], $icons['identity'], $license_row, $profile);
  $client['categories'][] = vl_constellation_infrastructure_category($palette['infrastructure'], $icons['infrastructure'], $license_row, $profile);
  $client['categories'][] = vl_constellation_security_category($palette['security'], $icons['security'], $profile);
  $client['categories'][] = vl_constellation_content_category($palette['content'], $icons['content'], $profile);
  $client['categories'][] = vl_constellation_plugins_category($palette['plugins'], $icons['plugins'], $profile);
  $client['categories'][] = vl_constellation_theme_category($palette['themes'], $icons['themes'], $profile);
  $client['categories'][] = vl_constellation_users_category($palette['users'], $icons['users'], $profile);
  $client['categories'][] = vl_constellation_ai_category($palette['ai'], $icons['ai'], $conversations);
  $client['categories'][] = vl_constellation_sessions_category($palette['sessions'], $icons['sessions'], $session_starts, $session_ends);
  $client['categories'][] = vl_constellation_integrations_category($palette['integrations'], $icons['integrations'], $connections);

  return $client;
}

function vl_constellation_identity_category(string $color, string $icon, array $license_row, array $profile): array {
  $nodes = [];
  $nodes[] = vl_constellation_node('client', 'Client', $color, 6, vl_constellation_string($license_row['client'] ?? 'Unassigned'));
  $nodes[] = vl_constellation_node('site', 'Primary Site', $color, 6, vl_constellation_string($license_row['site'] ?? ($profile['site'] ?? 'Unknown')));
  $nodes[] = vl_constellation_node('status', 'License Status', $color, !empty($license_row['active']) ? 8 : 4, !empty($license_row['active']) ? 'Active' : 'Inactive');
  $nodes[] = vl_constellation_node('heartbeat', 'Last Heartbeat', $color, 5, vl_constellation_time_ago($license_row['last_seen'] ?? 0));
  if (!empty($license_row['plugin_version'])) {
    $nodes[] = vl_constellation_node('widget_version', 'Widget Version', $color, 5, 'v' . vl_constellation_string($license_row['plugin_version']));
  } elseif (!empty($profile['wordpress']['version'])) {
    $nodes[] = vl_constellation_node('wordpress_version', 'WordPress Version', $color, 4, 'v' . vl_constellation_string($profile['wordpress']['version']));
  }

  return vl_constellation_category('identity', 'Identity & Licensing', $color, $icon, $nodes);
}

function vl_constellation_infrastructure_category(string $color, string $icon, array $license_row, array $profile): array {
  $nodes = [];
  $https = isset($profile['https']) ? (bool)$profile['https'] : null;
  $nodes[] = vl_constellation_node('https', 'HTTPS', $color, $https ? 7 : 4, $https === null ? 'Unknown' : ($https ? 'Secured' : 'Not secure'));

  $wp_version = $profile['wordpress']['version'] ?? ($license_row['wp_version'] ?? '');
  if ($wp_version) {
    $nodes[] = vl_constellation_node('wp_version', 'WordPress Core', $color, 5, 'v' . vl_constellation_string($wp_version));
  }

  $theme_name = $profile['wordpress']['theme']['name'] ?? '';
  if ($theme_name) {
    $nodes[] = vl_constellation_node('theme', 'Active Theme', $color, 5, vl_constellation_string($theme_name));
  }

  $plugin_count = is_array($profile['plugins'] ?? null) ? count($profile['plugins']) : 0;
  if ($plugin_count) {
    $nodes[] = vl_constellation_node('plugin_count', 'Plugins Installed', $color, min(10, max(3, $plugin_count)), $plugin_count . ' plugins');
  }

  $connections = is_array($profile['connections'] ?? null) ? $profile['connections'] : [];
  if ($connections) {
    $nodes[] = vl_constellation_node('connections', 'Remote Connections', $color, min(10, count($connections) + 3), count($connections) . ' integrations');
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('infrastructure_placeholder', 'Infrastructure', $color, 3, 'Awaiting telemetry');
  }

  return vl_constellation_category('infrastructure', 'Infrastructure & Platform', $color, $icon, $nodes);
}

function vl_constellation_security_category(string $color, string $icon, array $profile): array {
  $nodes = [];
  $security = is_array($profile['security'] ?? null) ? $profile['security'] : [];
  if ($security) {
    foreach (vl_constellation_flatten_security($security) as $row) {
      $nodes[] = vl_constellation_node($row['id'], $row['label'], $color, $row['value'], $row['detail']);
    }
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('security_placeholder', 'Security Signals', $color, 3, 'No security data reported');
  }

  return vl_constellation_category('security', 'Security & Compliance', $color, $icon, $nodes);
}

function vl_constellation_content_category(string $color, string $icon, array $profile): array {
  $nodes = [];
  $posts = is_array($profile['_posts'] ?? null) ? count($profile['_posts']) : (is_array($profile['posts'] ?? null) ? count($profile['posts']) : 0);
  $pages = is_array($profile['_pages'] ?? null) ? count($profile['_pages']) : 0;
  $media = is_array($profile['content']['media'] ?? null) ? count($profile['content']['media']) : 0;

  if ($posts) {
    $nodes[] = vl_constellation_node('posts', 'Published Posts', $color, min(10, max(3, $posts)), $posts . ' posts');
  }
  if ($pages) {
    $nodes[] = vl_constellation_node('pages', 'Published Pages', $color, min(9, max(3, $pages)), $pages . ' pages');
  }
  if ($media) {
    $nodes[] = vl_constellation_node('media', 'Media Items', $color, min(8, max(3, $media)), $media . ' assets');
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('content_placeholder', 'Content Footprint', $color, 3, 'Content metrics not synced yet');
  }

  return vl_constellation_category('content', 'Content Universe', $color, $icon, $nodes);
}

function vl_constellation_plugins_category(string $color, string $icon, array $profile): array {
  $nodes = [];
  $plugins = is_array($profile['plugins'] ?? null) ? $profile['plugins'] : [];

  $active = 0;
  foreach ($plugins as $plugin) {
    if (is_array($plugin) && !empty($plugin['is_active'])) {
      $active++;
    } elseif (is_array($plugin) && isset($plugin['status']) && stripos((string)$plugin['status'], 'active') !== false) {
      $active++;
    }
  }

  if ($plugins) {
    $nodes[] = vl_constellation_node('plugins_total', 'Installed Plugins', $color, min(10, max(3, count($plugins))), count($plugins) . ' total');
    $nodes[] = vl_constellation_node('plugins_active', 'Active Plugins', $color, min(10, max(3, $active)), $active . ' active');

    $top = array_slice($plugins, 0, 5);
    foreach ($top as $index => $plugin) {
      $label = vl_constellation_string($plugin['name'] ?? ($plugin['Name'] ?? 'Plugin ' . ($index + 1)));
      $version = vl_constellation_string($plugin['version'] ?? ($plugin['Version'] ?? ''));
      $detail = $version ? 'v' . $version : 'Version unknown';
      $nodes[] = vl_constellation_node('plugin_' . $index, $label, $color, 4, $detail);
    }
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('plugins_placeholder', 'Plugins', $color, 3, 'Plugins not reported');
  }

  return vl_constellation_category('plugins', 'Plugin Ecosystem', $color, $icon, $nodes);
}

function vl_constellation_theme_category(string $color, string $icon, array $profile): array {
  $nodes = [];
  $theme = is_array($profile['wordpress']['theme'] ?? null) ? $profile['wordpress']['theme'] : [];
  if ($theme) {
    $nodes[] = vl_constellation_node('theme_name', 'Theme Name', $color, 6, vl_constellation_string($theme['name'] ?? 'Theme'));
    if (!empty($theme['version'])) {
      $nodes[] = vl_constellation_node('theme_version', 'Theme Version', $color, 4, 'v' . vl_constellation_string($theme['version']));
    }
    $nodes[] = vl_constellation_node('theme_status', 'Active', $color, !empty($theme['is_active']) ? 6 : 3, !empty($theme['is_active']) ? 'Active' : 'Inactive');
  }

  $themes = is_array($profile['themes'] ?? null) ? $profile['themes'] : [];
  if ($themes) {
    $nodes[] = vl_constellation_node('themes_total', 'Available Themes', $color, min(8, max(3, count($themes))), count($themes) . ' themes');
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('themes_placeholder', 'Themes', $color, 3, 'Theme data not synced');
  }

  return vl_constellation_category('themes', 'Theme & Experience', $color, $icon, $nodes);
}

function vl_constellation_users_category(string $color, string $icon, array $profile): array {
  $nodes = [];
  $users = is_array($profile['users'] ?? null) ? $profile['users'] : (is_array($profile['_users'] ?? null) ? $profile['_users'] : []);

  if ($users) {
    $nodes[] = vl_constellation_node('users_total', 'User Accounts', $color, min(9, max(3, count($users))), count($users) . ' users');
    $roles = [];
    foreach ($users as $user) {
      if (!is_array($user)) continue;
      $role = $user['role'] ?? ($user['roles'][0] ?? 'user');
      $role = is_array($role) ? ($role[0] ?? 'user') : $role;
      $role = strtolower((string)$role);
      $roles[$role] = ($roles[$role] ?? 0) + 1;
    }
    arsort($roles);
    foreach (array_slice($roles, 0, 4, true) as $role => $count) {
      $nodes[] = vl_constellation_node('role_' . preg_replace('/[^a-z0-9]/', '_', $role), ucwords(str_replace('_', ' ', $role)), $color, min(8, max(3, $count + 3)), $count . ' users');
    }
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('users_placeholder', 'Users', $color, 3, 'User roster not available');
  }

  return vl_constellation_category('users', 'User Accounts & Roles', $color, $icon, $nodes);
}

function vl_constellation_ai_category(string $color, string $icon, array $conversations): array {
  $nodes = [];

  $conversation_count = count($conversations);
  if ($conversation_count) {
    $nodes[] = vl_constellation_node('conversations_total', 'Conversations', $color, min(10, max(4, $conversation_count + 3)), $conversation_count . ' logged');

    $messages = 0;
    $last = 0;
    foreach ($conversations as $conversation) {
      if (!is_array($conversation)) continue;
      $messages += is_array($conversation['transcript'] ?? null) ? count($conversation['transcript']) : 0;
      $ended = $conversation['timestamp'] ?? ($conversation['received_at'] ?? 0);
      if ($ended > $last) $last = (int)$ended;
    }
    if ($messages) {
      $nodes[] = vl_constellation_node('messages', 'Messages', $color, min(9, max(3, $messages / 2)), $messages . ' exchanges');
    }
    if ($last) {
      $nodes[] = vl_constellation_node('last_conversation', 'Last Conversation', $color, 6, vl_constellation_time_ago($last));
    }
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('conversations_placeholder', 'AI Chats', $color, 3, 'No conversations logged');
  }

  return vl_constellation_category('ai', 'AI Conversations', $color, $icon, $nodes);
}

function vl_constellation_sessions_category(string $color, string $icon, array $session_starts, array $session_ends): array {
  $nodes = [];
  $start_count = count($session_starts);
  $end_count   = count($session_ends);

  if ($start_count) {
    $nodes[] = vl_constellation_node('sessions_started', 'Sessions Started', $color, min(9, max(3, $start_count + 2)), $start_count . ' sessions');
  }
  if ($end_count) {
    $nodes[] = vl_constellation_node('sessions_closed', 'Sessions Closed', $color, min(9, max(3, $end_count + 2)), $end_count . ' sessions');
  }

  $timeouts = 0;
  $last_end = 0;
  foreach ($session_ends as $session) {
    if (!is_array($session)) continue;
    $reason = strtolower((string)($session['reason'] ?? ''));
    if (strpos($reason, 'timeout') !== false || strpos($reason, 'inactive') !== false) {
      $timeouts++;
    }
    $ended = $session['timestamp'] ?? ($session['ended_at'] ?? 0);
    if ($ended > $last_end) $last_end = (int)$ended;
  }

  if ($timeouts) {
    $nodes[] = vl_constellation_node('session_timeouts', 'Inactive Closures', $color, min(8, max(3, $timeouts + 2)), $timeouts . ' auto-closed');
  }
  if ($last_end) {
    $nodes[] = vl_constellation_node('last_session', 'Last Session', $color, 5, vl_constellation_time_ago($last_end));
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('sessions_placeholder', 'Sessions', $color, 3, 'No session telemetry yet');
  }

  return vl_constellation_category('sessions', 'Sessions & Engagement', $color, $icon, $nodes);
}

function vl_constellation_integrations_category(string $color, string $icon, array $connections): array {
  $nodes = [];
  if ($connections) {
    $nodes[] = vl_constellation_node('integrations_total', 'Integrations', $color, min(9, max(3, count($connections) + 2)), count($connections) . ' connected');
    $index = 0;
    foreach ($connections as $key => $row) {
      if ($index >= 5) break;
      if (is_array($row)) {
        $provider = $row['provider'] ?? ($row['name'] ?? $key);
        $status = !empty($row['status']) ? vl_constellation_string($row['status']) : (!empty($row['connected']) ? 'Connected' : 'Unknown');
      } else {
        $provider = $key;
        $status = is_scalar($row) ? (string)$row : 'Available';
      }
      $nodes[] = vl_constellation_node('integration_' . $index, vl_constellation_string((string)$provider), $color, 4, $status);
      $index++;
    }
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('integrations_placeholder', 'Cloud Integrations', $color, 3, 'No connections synced');
  }

  return vl_constellation_category('integrations', 'Integrations & Signals', $color, $icon, $nodes);
}

function vl_constellation_category(string $slug, string $label, string $color, string $icon, array $nodes): array {
  return [
    'slug'  => $slug,
    'name'  => $label,
    'color' => $color,
    'icon'  => $icon,
    'nodes' => array_values($nodes),
  ];
}

function vl_constellation_node(string $id, string $label, string $color, int $value, string $detail): array {
  return [
    'id'     => $id,
    'label'  => $label,
    'color'  => $color,
    'value'  => max(1, $value),
    'detail' => $detail,
  ];
}

function vl_constellation_flatten_security(array $security): array {
  $nodes = [];
  $index = 0;

  $walker = function ($prefix, $value) use (&$nodes, &$walker, &$index) {
    if (is_array($value)) {
      foreach ($value as $key => $child) {
        $walker(trim($prefix . ' ' . vl_constellation_human_label((string)$key)), $child);
      }
      return;
    }

    $label = trim($prefix);
    if ($label === '') {
      $label = 'Security Signal';
    }

    $detail = '';
    $score  = 4;

    if (is_bool($value)) {
      $detail = $value ? 'Enabled' : 'Disabled';
      $score = $value ? 7 : 3;
    } elseif (is_numeric($value)) {
      $detail = (string)$value;
      $score = (int)max(3, min(10, abs((float)$value) + 3));
    } elseif (is_string($value)) {
      $detail = trim($value) === '' ? 'Unavailable' : vl_constellation_string($value);
      $score = 4;
    } else {
      $detail = 'Reported';
    }

    $nodes[] = [
      'id'    => 'security_' . $index++,
      'label' => $label,
      'value' => $score,
      'detail'=> $detail,
    ];
  };

  $walker('', $security);

  return $nodes;
}

function vl_constellation_time_ago($timestamp): string {
  $timestamp = is_numeric($timestamp) ? (int)$timestamp : strtotime((string)$timestamp);
  if (!$timestamp) {
    return 'No activity recorded';
  }
  $diff = time() - $timestamp;
  if ($diff < 0) $diff = 0;

  $units = [
    ['year', 365*24*3600],
    ['month', 30*24*3600],
    ['day', 24*3600],
    ['hour', 3600],
    ['minute', 60],
    ['second', 1],
  ];

  foreach ($units as [$name, $secs]) {
    if ($diff >= $secs) {
      $value = (int)floor($diff / $secs);
      return $value . ' ' . $name . ($value === 1 ? '' : 's') . ' ago';
    }
  }

  return 'Just now';
}

function vl_constellation_date($timestamp): string {
  if (empty($timestamp)) {
    return '';
  }
  if (is_numeric($timestamp)) {
    return date('c', (int)$timestamp);
  }
  $parsed = strtotime((string)$timestamp);
  return $parsed ? date('c', $parsed) : '';
}

function vl_constellation_string($value): string {
  return trim(wp_strip_all_tags((string)$value));
}

function vl_constellation_redact_key(string $key): string {
  $key = trim($key);
  if ($key === '') {
    return '';
  }
  if (strlen($key) <= 6) {
    return str_repeat('•', strlen($key));
  }
  return substr($key, 0, 4) . '…' . substr($key, -4);
}

function vl_constellation_human_label(string $key): string {
  $key = trim($key);
  if ($key === '') return 'Item';
  $key = str_replace(['_', '-'], ' ', $key);
  return ucwords(preg_replace('/\s+/', ' ', $key));
}

/**
 * Field validation endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/validate/field', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $field = $req->get_param('field');
      if (!$field) {
        return new WP_REST_Response(['error' => 'Field name required'], 400);
      }
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Get client profile data
      $profiles = get_option('vl_hub_profiles', []);
      $profile = $profiles[$license_id] ?? [];
      
      // Validate the specific field
      $validation_result = vl_validate_field_mapping($profile, $field);
      
      return new WP_REST_Response([
        'field' => $field,
        'valid' => $validation_result['valid'],
        'value' => $validation_result['value'],
        'error' => $validation_result['error'] ?? null,
        'timestamp' => current_time('mysql')
      ], 200);
    }
  ]);
});

/**
 * Validate all fields endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/validate/all', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Get client profile data
      $profiles = get_option('vl_hub_profiles', []);
      $profile = $profiles[$license_id] ?? [];
      
      // Validate all fields
      $all_fields = [
        'tls_status', 'tls_version', 'tls_issuer', 'tls_provider_guess',
        'tls_valid_from', 'tls_valid_to', 'tls_host',
        'waf_provider', 'waf_last_audit',
        'ids_provider', 'ids_last_scan', 'ids_result', 'ids_schedule',
        'auth_mfa', 'auth_password_policy', 'auth_session_timeout', 'auth_sso_providers',
        'domain_registrar', 'domain_registered_on', 'domain_renewal_date', 'domain_auto_renew', 'domain_dns_records'
      ];
      
      $results = [];
      foreach ($all_fields as $field) {
        $results[$field] = vl_validate_field_mapping($profile, $field);
      }
      
      return new WP_REST_Response([
        'license_id' => $license_id,
        'validations' => $results,
        'timestamp' => current_time('mysql')
      ], 200);
    }
  ]);
});

/**
 * Field validation helper function
 */
function vl_validate_field_mapping($profile, $field) {
  $security = $profile['security'] ?? [];
  
  switch ($field) {
    case 'tls_status':
      $value = $security['tls']['status'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS status not found' : null
      ];
      
    case 'tls_version':
      $value = $security['tls']['version'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS version not found' : null
      ];
      
    case 'tls_issuer':
      $value = $security['tls']['issuer'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS issuer not found' : null
      ];
      
    case 'tls_provider_guess':
      $value = $security['tls']['provider_guess'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS provider guess not found' : null
      ];
      
    case 'tls_valid_from':
      $value = $security['tls']['valid_from'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS valid from date not found' : null
      ];
      
    case 'tls_valid_to':
      $value = $security['tls']['valid_to'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS valid to date not found' : null
      ];
      
    case 'tls_host':
      $value = $security['tls']['host'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS host not found' : null
      ];
      
    case 'waf_provider':
      $value = $security['waf']['provider'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'WAF provider not found' : null
      ];
      
    case 'waf_last_audit':
      $value = $security['waf']['last_audit'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'WAF last audit not found' : null
      ];
      
    case 'ids_provider':
      $value = $security['ids']['provider'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'IDS provider not found' : null
      ];
      
    case 'ids_last_scan':
      $value = $security['ids']['last_scan'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'IDS last scan not found' : null
      ];
      
    case 'ids_result':
      $value = $security['ids']['result'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'IDS result not found' : null
      ];
      
    case 'ids_schedule':
      $value = $security['ids']['schedule'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'IDS schedule not found' : null
      ];
      
    case 'auth_mfa':
      $value = $security['auth']['mfa'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'MFA not found' : null
      ];
      
    case 'auth_password_policy':
      $value = $security['auth']['password_policy'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'Password policy not found' : null
      ];
      
    case 'auth_session_timeout':
      $value = $security['auth']['session_timeout'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'Session timeout not found' : null
      ];
      
    case 'auth_sso_providers':
      $value = $security['auth']['sso_providers'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'SSO providers not found' : null
      ];
      
    case 'domain_registrar':
      $value = $security['domain']['registrar'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'Domain registrar not found' : null
      ];
      
    case 'domain_registered_on':
      $value = $security['domain']['registered_on'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'Domain registration date not found' : null
      ];
      
    case 'domain_renewal_date':
      $value = $security['domain']['renewal_date'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'Domain renewal date not found' : null
      ];
      
    case 'domain_auto_renew':
      $value = $security['domain']['auto_renew'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'Domain auto-renewal setting not found' : null
      ];
      
    case 'domain_dns_records':
      $value = $security['domain']['dns_records'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'DNS records not found' : null
      ];
      
    default:
  return [
        'valid' => false,
        'value' => '',
        'error' => 'Unknown field: ' . $field
      ];
  }
}

/**
 * Test endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/test', [
    'methods' => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      return new WP_REST_Response([
        'status' => 'ok',
        'message' => 'Luna Hub test endpoint working',
        'license' => $req->get_param('license') ?: 'none',
      ], 200);
    }
  ]);
});