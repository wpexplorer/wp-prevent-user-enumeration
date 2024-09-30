<?php
/**
 * Plugin Name:       WP Prevent User Enumeration
 * Plugin URI:        https://github.com/wpexplorer/wp-prevent-user-enumeration/
 * Description:       Helps prevent user enumeration in WordPress by disabling certain core features.
 * Version:           1.0
 * Requires at least: 6.6
 * Requires PHP:      8.0
 * Author:            WPExplorer
 * Author URI:        https://www.wpexplorer.com/
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-prevent-user-enumeration
 */

/*
WP Prevent User Enumeration is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
any later version.

WP Prevent User Enumeration is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with WP Prevent User Enumeration. If not, see https://www.gnu.org/licenses/gpl-2.0.html.
*/

/**
 * Prevent direct access to this file.
 */
defined( 'ABSPATH' ) || exit;

if ( ! class_exists( 'WP_Prevent_User_Enumeration' ) ) {

    class WP_Prevent_User_Enumeration {

        /**
         * Static-only class.
         */
        private function __construct() {}

        /**
         * Init.
         */
        public static function init() {
            add_filter( 'login_errors', [ self::class, 'modify_login_errors' ] );
            add_action( 'init', [ self::class, 'prevent_author_requests' ] );
            add_action( 'rest_authentication_errors', [ self::class, 'only_allow_logged_in_rest_access_to_users' ] );
            add_filter( 'wp_sitemaps_add_provider', [ self::class, 'remove_authors_from_sitemap' ], 10, 2 );
            add_filter( 'oembed_response_data', [ self::class, 'remove_author_from_oembed' ] );
            add_action( 'template_redirect', [ self::class, 'redirect_author_archives' ] );
            add_filter( 'the_author_posts_link', [ self::class, 'modify_the_author_posts_link' ] );
        }

        /**
         * Check request.
         */
        public static function modify_login_errors() {
            return 'An error occurred. Try again or if you are a bot, please don\'t.';
        }

        /**
         * Check request.
         */
        public static function prevent_author_requests() {
            if ( isset( $_REQUEST['author'] )
                && self::string_contains_numbers( $_REQUEST['author'] )
                && ! is_user_logged_in()
            ) {
                wp_die( 'forbidden - number in author name not allowed = ' . esc_html( $_REQUEST['author'] ) );
            }
        }

        /**
         * Only allow logged in access to users in rest API.
         */
        public static function only_allow_logged_in_rest_access_to_users( $access ) {
            if ( is_user_logged_in() ) {
                return $access;
            }

            if ( ( preg_match( '/users/i', $_SERVER['REQUEST_URI'] ) !== 0 )
                || ( isset( $_REQUEST['rest_route'] ) && ( preg_match( '/users/i', $_REQUEST['rest_route'] ) !== 0 ) )
            ) {
                return new \WP_Error(
                    'rest_cannot_access',
                    'Only authenticated users can access the User endpoint REST API.',
                    [
                        'status' => rest_authorization_required_code()
                    ]
                );
            }

            return $access;
        }

        /**
         * Returns true if string contains numbers.
         */
        private static function string_contains_numbers( $string ): bool {
            return preg_match( '/\\d/', $string ) > 0;
        }

        /**
         * Remove authors from sitemap.
         */
        public static function remove_authors_from_sitemap( $provider, $name ) {
            if ( 'users' === $name ) {
                return false;
            }

            return $provider;
        }

        /**
         * Remove authors from sitemap.
         */
        public static function remove_author_from_oembed( $data ) {
            unset( $data['author_url'] );
            unset( $data['author_name'] );

            return $data;
        }

        /**
         * Redirects the author archives to the site homepage.
         */
        public static function redirect_author_archives() {
            if ( is_author() || isset( $_GET['author'] ) ) {
                wp_safe_redirect( esc_url( home_url( '/' ) ), 301 );
            }
        }

        /**
         * Modify the authors post link.
         */
        public static function modify_the_author_posts_link( $link ) {
            if ( ! is_admin() ) {
                return get_the_author();
            }
            return $link;
        }

    }

    WP_Prevent_User_Enumeration::init();
}
