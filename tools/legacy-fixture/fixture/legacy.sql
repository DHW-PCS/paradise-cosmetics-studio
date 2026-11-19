-- Blessing Skin Server 6.0.2 synthetic export. Prepare with go run ./tools/legacy-fixture.
-- Import only into a fresh database. The @pcs_* variables are filled during preparation.
/*M!999999\- enable the sandbox mode */

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `invitation_codes` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `code` varchar(255) NOT NULL,
  `generated_at` datetime NOT NULL,
  `used_by` int(11) NOT NULL DEFAULT 0,
  `used_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `invitation_codes` WRITE;
/*!40000 ALTER TABLE `invitation_codes` DISABLE KEYS */;
INSERT INTO `invitation_codes` VALUES
(1,@pcs_used_invite,'2026-11-18 08:00:00',1,'2026-11-18 08:30:00'),
(2,@pcs_unused_invite,'2026-11-19 08:30:00',0,NULL);
/*!40000 ALTER TABLE `invitation_codes` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `jobs` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `queue` varchar(255) NOT NULL,
  `payload` longtext NOT NULL,
  `attempts` tinyint(3) unsigned NOT NULL,
  `reserved_at` int(10) unsigned DEFAULT NULL,
  `available_at` int(10) unsigned NOT NULL,
  `created_at` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `jobs_queue_index` (`queue`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `jobs` WRITE;
/*!40000 ALTER TABLE `jobs` DISABLE KEYS */;
/*!40000 ALTER TABLE `jobs` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `language_lines` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `group` varchar(255) NOT NULL,
  `key` varchar(255) NOT NULL,
  `text` text NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `language_lines_group_index` (`group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `language_lines` WRITE;
/*!40000 ALTER TABLE `language_lines` DISABLE KEYS */;
/*!40000 ALTER TABLE `language_lines` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `migrations` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `migration` varchar(255) NOT NULL,
  `batch` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=25 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `migrations` WRITE;
/*!40000 ALTER TABLE `migrations` DISABLE KEYS */;
INSERT INTO `migrations` VALUES
(1,'2016_06_01_000001_create_oauth_auth_codes_table',1),
(2,'2016_06_01_000002_create_oauth_access_tokens_table',1),
(3,'2016_06_01_000003_create_oauth_refresh_tokens_table',1),
(4,'2016_06_01_000004_create_oauth_clients_table',1),
(5,'2016_06_01_000005_create_oauth_personal_access_clients_table',1),
(6,'2016_11_18_133939_create_all_tables',1),
(7,'2016_11_18_134542_import_options',1),
(8,'2018_07_26_130617_add_verification_to_users_table',1),
(9,'2018_08_21_105514_add_remember_token_to_users_table',1),
(10,'2019_03_01_131420_add_tid_skin',1),
(11,'2019_03_13_130311_rename_players_table_columns',1),
(12,'2019_03_14_174727_create_closet',1),
(13,'2019_03_16_162603_remove_likes_field',1),
(14,'2019_03_23_171728_create_report_table',1),
(15,'2019_05_05_103143_add_likes_field',1),
(16,'2019_07_03_094434_create_notifications_table',1),
(17,'2019_07_05_222912_create_jobs_table',1),
(18,'2019_09_05_130811_create_language_lines_table',1),
(19,'2019_12_14_095751_update_ip_field',1),
(20,'2020_03_10_145738_lengthen_ip_field',1),
(21,'2020_06_26_090510_add_o_auth_provider_field',1),
(22,'2020_06_28_155519_add_user_locale_field',1),
(23,'2021_04_14_181300_create_scope_table',1),
(24,'2021_06_06_111049_add_is_dark_mode_field',1);
/*!40000 ALTER TABLE `migrations` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `notifications` (
  `id` char(36) NOT NULL,
  `type` varchar(255) NOT NULL,
  `notifiable_type` varchar(255) NOT NULL,
  `notifiable_id` bigint(20) unsigned NOT NULL,
  `data` text NOT NULL,
  `read_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `notifications_notifiable_type_notifiable_id_index` (`notifiable_type`,`notifiable_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `notifications` WRITE;
/*!40000 ALTER TABLE `notifications` DISABLE KEYS */;
INSERT INTO `notifications` VALUES
('f1f1f1f1-1111-4111-8111-111111111111','App\\Notifications\\SiteMessage','App\\Models\\User',1,'{\"title\":\"Fixture unread notice\",\"content\":\"Synthetic unread notification for migration verification.\"}',NULL,'2026-11-19 09:15:00','2026-11-19 09:15:00'),
('f2f2f2f2-2222-4222-8222-222222222222','App\\Notifications\\SiteMessage','App\\Models\\User',1,'{\"title\":\"Fixture read notice\",\"content\":\"Synthetic read notification for migration verification.\"}','2026-11-19 09:18:00','2026-11-19 09:16:00','2026-11-19 09:18:00');
/*!40000 ALTER TABLE `notifications` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `oauth_access_tokens` (
  `id` varchar(100) NOT NULL,
  `user_id` bigint(20) unsigned DEFAULT NULL,
  `client_id` bigint(20) unsigned NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `scopes` text DEFAULT NULL,
  `revoked` tinyint(1) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `expires_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `oauth_access_tokens_user_id_index` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `oauth_access_tokens` WRITE;
/*!40000 ALTER TABLE `oauth_access_tokens` DISABLE KEYS */;
/*!40000 ALTER TABLE `oauth_access_tokens` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `oauth_auth_codes` (
  `id` varchar(100) NOT NULL,
  `user_id` bigint(20) unsigned NOT NULL,
  `client_id` bigint(20) unsigned NOT NULL,
  `scopes` text DEFAULT NULL,
  `revoked` tinyint(1) NOT NULL,
  `expires_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `oauth_auth_codes_user_id_index` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `oauth_auth_codes` WRITE;
/*!40000 ALTER TABLE `oauth_auth_codes` DISABLE KEYS */;
/*!40000 ALTER TABLE `oauth_auth_codes` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `oauth_clients` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  `secret` varchar(100) DEFAULT NULL,
  `provider` varchar(255) DEFAULT NULL,
  `redirect` text NOT NULL,
  `personal_access_client` tinyint(1) NOT NULL,
  `password_client` tinyint(1) NOT NULL,
  `revoked` tinyint(1) NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `oauth_clients_user_id_index` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `oauth_clients` WRITE;
/*!40000 ALTER TABLE `oauth_clients` DISABLE KEYS */;
INSERT INTO `oauth_clients` VALUES
(1,1,'Fixture Authorization Code',@pcs_oauth_code_secret,NULL,'http://127.0.0.1:18862/callback',0,0,0,'2026-11-19 10:18:36','2026-11-19 10:18:36'),
(2,NULL,'Fixture Personal Access',@pcs_oauth_personal_secret,NULL,'http://localhost',1,0,0,'2026-11-19 10:18:37','2026-11-19 10:18:37');
/*!40000 ALTER TABLE `oauth_clients` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `oauth_personal_access_clients` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `client_id` bigint(20) unsigned NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `oauth_personal_access_clients` WRITE;
/*!40000 ALTER TABLE `oauth_personal_access_clients` DISABLE KEYS */;
INSERT INTO `oauth_personal_access_clients` VALUES
(1,2,'2026-11-19 10:18:37','2026-11-19 10:18:37');
/*!40000 ALTER TABLE `oauth_personal_access_clients` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `oauth_refresh_tokens` (
  `id` varchar(100) NOT NULL,
  `access_token_id` varchar(100) NOT NULL,
  `revoked` tinyint(1) NOT NULL,
  `expires_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `oauth_refresh_tokens_access_token_id_index` (`access_token_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `oauth_refresh_tokens` WRITE;
/*!40000 ALTER TABLE `oauth_refresh_tokens` DISABLE KEYS */;
/*!40000 ALTER TABLE `oauth_refresh_tokens` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `options` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `option_name` varchar(50) NOT NULL,
  `option_value` longtext NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=64 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `options` WRITE;
/*!40000 ALTER TABLE `options` DISABLE KEYS */;
INSERT INTO `options` VALUES
(1,'site_url','http://127.0.0.1:18080'),
(2,'site_name','PCS Legacy Fixture'),
(3,'site_description','Open-source PHP Minecraft Skin Hosting Service'),
(4,'register_with_player_name','true'),
(5,'require_verification','false'),
(6,'regs_per_ip','3'),
(7,'announcement','Welcome to Blessing Skin 6.0.2!'),
(8,'home_pic_url','./app/bg.webp'),
(9,'custom_css',''),
(10,'custom_js',''),
(11,'player_name_rule','official'),
(12,'custom_player_name_regexp',''),
(13,'player_name_length_min','3'),
(14,'player_name_length_max','16'),
(15,'user_initial_score','1000'),
(16,'sign_gap_time','24'),
(17,'sign_score','10,100'),
(18,'score_per_storage','true'),
(19,'private_score_per_storage','10'),
(20,'return_score','true'),
(21,'score_per_player','100'),
(22,'sign_after_zero','false'),
(23,'version','6.0.2'),
(24,'copyright_text','<b>Copyright &copy; 2026 <a href=\"{site_url}\">{site_name}</a>.</b> All rights reserved.'),
(25,'auto_del_invalid_texture','false'),
(26,'allow_downloading_texture','true'),
(27,'texture_name_regexp',''),
(28,'cache_expire_time','31536000'),
(29,'max_upload_file_size','1024'),
(30,'force_ssl','false'),
(31,'auto_detect_asset_url','true'),
(32,'plugins_enabled','[{\"name\":\"invitation-codes\",\"version\":\"3.1.2\"},{\"name\":\"legacy-api\",\"version\":\"1.1.3\"},{\"name\":\"yggdrasil-api\",\"version\":\"5.2.1\"},{\"name\":\"oauth\",\"version\":\"1.0.6\"}]'),
(33,'copyright_prefer','0'),
(34,'score_per_closet_item','0'),
(35,'favicon_url','app/favicon.ico'),
(36,'score_award_per_texture','0'),
(37,'take_back_scores_after_deletion','true'),
(38,'score_award_per_like','0'),
(39,'meta_keywords',''),
(40,'meta_description',''),
(41,'meta_extras',''),
(42,'cdn_address',''),
(43,'recaptcha_sitekey',''),
(44,'recaptcha_secretkey',''),
(45,'recaptcha_invisible','false'),
(46,'reporter_score_modification','0'),
(47,'reporter_reward_score','0'),
(48,'content_policy',''),
(49,'transparent_navbar','false'),
(50,'status_code_for_private','403'),
(51,'navbar_color','cyan'),
(52,'sidebar_color','dark-maroon'),
(53,'ygg_uuid_algorithm','v3'),
(54,'ygg_token_expire_1','259200'),
(55,'ygg_token_expire_2','604800'),
(56,'ygg_tokens_limit','10'),
(57,'ygg_rate_limit','1000'),
(58,'ygg_skin_domain',''),
(59,'ygg_search_profile_max','5'),
(60,'ygg_private_key',@pcs_ygg_private_key),
(61,'ygg_show_config_section','true'),
(62,'ygg_show_activities_section','true'),
(63,'ygg_enable_ali','true');
/*!40000 ALTER TABLE `options` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `players` (
  `pid` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uid` int(11) NOT NULL,
  `name` varchar(50) NOT NULL,
  `tid_cape` int(11) NOT NULL DEFAULT 0,
  `last_modified` datetime NOT NULL,
  `tid_skin` int(11) NOT NULL DEFAULT -1,
  PRIMARY KEY (`pid`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `players` WRITE;
/*!40000 ALTER TABLE `players` DISABLE KEYS */;
INSERT INTO `players` VALUES
(1,1,'NormalPlayer',3,'2026-11-19 09:05:00',1),
(2,1,'SecondPlayer',0,'2026-11-19 10:16:36',-1),
(3,4,'AdminPlayer',0,'2026-11-19 10:16:36',-1);
/*!40000 ALTER TABLE `players` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `reports` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `tid` int(11) NOT NULL,
  `uploader` int(11) NOT NULL,
  `reporter` int(11) NOT NULL,
  `reason` longtext NOT NULL,
  `status` int(11) NOT NULL,
  `report_at` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `reports` WRITE;
/*!40000 ALTER TABLE `reports` DISABLE KEYS */;
INSERT INTO `reports` VALUES
(1,2,2,1,'synthetic fixture report',0,'2026-11-19 10:16:36'),
(2,4,4,1,'fixture pending report 2026-11-19',0,'2026-11-19 09:10:00'),
(3,2,2,1,'fixture processed report 2026-11-19',1,'2026-11-19 09:12:00');
/*!40000 ALTER TABLE `reports` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `scopes` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `description` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `scopes_name_unique` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `scopes` WRITE;
/*!40000 ALTER TABLE `scopes` DISABLE KEYS */;
/*!40000 ALTER TABLE `scopes` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `textures` (
  `tid` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `type` varchar(10) NOT NULL,
  `hash` varchar(64) NOT NULL,
  `size` int(11) NOT NULL,
  `uploader` int(11) NOT NULL,
  `public` tinyint(4) NOT NULL,
  `upload_at` datetime NOT NULL,
  `likes` int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`tid`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `textures` WRITE;
/*!40000 ALTER TABLE `textures` DISABLE KEYS */;
INSERT INTO `textures` VALUES
(1,'Steve','steve','4c7b0468044bfecacc43d00a3a69335a834b73937688292c20d3988cae58248d',2,1,1,'2026-11-19 10:16:36',1),
(2,'Alex','alex','59dcbcf46ae3aa1caa8732fa6139234b1f888143bf20523cac0c26d82cb8a2cf',2,2,0,'2026-11-19 10:16:36',1),
(3,'Cape','cape','c82618d092a43a52a4a5c44c30e9d980bb837b54caf1654d6924bada3b8363a7',2,1,1,'2026-11-19 10:16:36',1),
(4,'HD','steve','803743fcbb26fa8616999128f2e9f029b2b66d63de0c110c06ceeed1b4ae2694',3,4,1,'2026-11-19 10:16:36',1),
(5,'SteveSharedPrivate','steve','4c7b0468044bfecacc43d00a3a69335a834b73937688292c20d3988cae58248d',2,3,0,'2026-11-19 10:16:36',1),
(6,'MissingFile','steve','615029ab5acf3331a831a58c0f8da16891af2fe5ce7f73e43d9d91534ec24097',1,1,0,'2026-11-19 10:16:36',1);
/*!40000 ALTER TABLE `textures` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_closet` (
  `user_uid` int(11) NOT NULL,
  `texture_tid` int(11) NOT NULL,
  `item_name` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `user_closet` WRITE;
/*!40000 ALTER TABLE `user_closet` DISABLE KEYS */;
INSERT INTO `user_closet` VALUES
(1,2,'closet-item-2'),
(1,4,'closet-item-4'),
(4,1,'closet-item-1');
/*!40000 ALTER TABLE `user_closet` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `uid` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `email` varchar(100) NOT NULL,
  `nickname` varchar(50) NOT NULL DEFAULT '',
  `locale` varchar(255) DEFAULT NULL,
  `score` int(11) NOT NULL,
  `avatar` int(11) NOT NULL DEFAULT 0,
  `password` varchar(255) NOT NULL,
  `ip` varchar(45) NOT NULL,
  `is_dark_mode` tinyint(1) NOT NULL DEFAULT 0,
  `permission` int(11) NOT NULL DEFAULT 0,
  `last_sign_at` datetime NOT NULL,
  `register_at` datetime NOT NULL,
  `verified` tinyint(1) NOT NULL DEFAULT 0,
  `verification_token` varchar(255) NOT NULL DEFAULT '',
  `remember_token` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`uid`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES
(1,'normal@example.invalid','NormalUser','en',137,1,@pcs_bcrypt_hash,'127.0.0.1',0,0,'2026-11-19 10:16:36','2026-11-19 10:16:36',1,'',NULL),
(2,'unverified@example.invalid','UnverifiedUser','en',100,0,@pcs_bcrypt_hash,'127.0.0.1',0,0,'2026-11-19 10:16:36','2026-11-19 10:16:36',0,'',NULL),
(3,'banned@example.invalid','BannedUser','en',100,0,@pcs_bcrypt_hash,'127.0.0.1',0,-1,'2026-11-19 10:16:36','2026-11-19 10:16:36',1,'',NULL),
(4,'admin@example.invalid','AdminUser','en',100,0,@pcs_bcrypt_hash,'127.0.0.1',0,1,'2026-11-19 10:16:36','2026-11-19 10:16:36',1,'',NULL),
(5,'super@example.invalid','SuperAdminUser','en',100,0,@pcs_bcrypt_hash,'127.0.0.1',0,2,'2026-11-19 10:16:36','2026-11-19 10:16:36',1,'',NULL),
(6,'emptyemail@example.invalid','','en',100,0,@pcs_salted2sha256_hash,'127.0.0.1',0,0,'2026-11-19 10:16:36','2026-11-19 10:16:36',0,'',NULL),
(7,'legacy-md5@example.invalid','LegacyMd5','en',100,0,@pcs_md5_hash,'127.0.0.1',0,0,'2026-11-19 10:16:36','2026-11-19 10:16:36',1,'',NULL),
(8,'legacy-sha256@example.invalid','LegacySha256','en',100,0,@pcs_sha256_hash,'127.0.0.1',0,0,'2026-11-19 10:16:36','2026-11-19 10:16:36',1,'',NULL),
(9,'','EmptyEmailUser','en',100,0,@pcs_bcrypt_hash,'127.0.0.1',0,0,'2026-11-19 10:16:36','2026-11-19 10:16:36',0,'',NULL);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `uuid` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `uuid` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `uuid` WRITE;
/*!40000 ALTER TABLE `uuid` DISABLE KEYS */;
INSERT INTO `uuid` VALUES
(1,'NormalPlayer','11111111111141118111111111111111'),
(2,'SecondPlayer','22222222222242228222222222222222'),
(3,'AdminPlayer','33333333333343338333333333333333');
/*!40000 ALTER TABLE `uuid` ENABLE KEYS */;
UNLOCK TABLES;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `ygg_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `action` varchar(255) NOT NULL,
  `user_id` int(11) NOT NULL,
  `player_id` int(11) NOT NULL,
  `parameters` varchar(255) NOT NULL DEFAULT '',
  `ip` varchar(255) NOT NULL DEFAULT '',
  `time` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

LOCK TABLES `ygg_log` WRITE;
/*!40000 ALTER TABLE `ygg_log` DISABLE KEYS */;
INSERT INTO `ygg_log` VALUES
(1,'authenticate',1,0,'{\"clientToken\":\"fixture-client-token\",\"agent\":{\"name\":\"Minecraft\",\"version\":1}}','127.0.0.1','2026-11-19 09:30:00'),
(2,'join',1,1,'{\"serverId\":\"fixture-server-id\"}','127.0.0.1','2026-11-19 09:30:00');
/*!40000 ALTER TABLE `ygg_log` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
