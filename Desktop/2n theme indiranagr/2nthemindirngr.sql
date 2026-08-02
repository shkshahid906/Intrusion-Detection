-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Aug 02, 2026 at 05:53 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `vapesbanglore`
--

-- --------------------------------------------------------

--
-- Table structure for table `about_us`
--

CREATE TABLE `about_us` (
  `id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `image_path` varchar(255) DEFAULT NULL,
  `images` text DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `about_us`
--

INSERT INTO `about_us` (`id`, `title`, `description`, `image_path`, `images`, `updated_at`) VALUES
(1, 'Elevating Your Vaping Experience in Koramangala', '<p>Welcome to <strong>Vape Shop Koramangala</strong>, your premium destination for top-quality vaping products in Koramangala, Indira Nagar. We believe in providing an unparalleled selection of devices, e-liquids, and accessories that cater to both beginners and seasoned cloud chasers.</p><p>Our mission is simple: to offer authentic products, 45-minute express delivery across Koramangala & nearby Indira Nagar areas, and exceptional customer service. We handpick every brand we stock to ensure you get nothing but the best.</p>', '/uploads/cms/1782561491989-871527695.png', '[\"/uploads/cms/vape_ad_1_1782635035479.png\",\"/uploads/cms/vape_ad_2_1782635056661.png\",\"/uploads/cms/vape_ad_3_1782635098584.png\",\"/uploads/cms/vape_ad_4_1782635130005.png\"]', '2026-08-02 15:33:54');

-- --------------------------------------------------------

--
-- Table structure for table `admins`
--

CREATE TABLE `admins` (
  `id` int(11) NOT NULL,
  `full_name` varchar(100) NOT NULL,
  `email` varchar(150) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('super_admin','admin') DEFAULT 'admin',
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `admins`
--

INSERT INTO `admins` (`id`, `full_name`, `email`, `password`, `role`, `status`, `created_at`, `updated_at`) VALUES
(1, 'Admin', 'admin@vapesbanglore.com', '$2b$10$69P0FcO7Yj.zXDN0jKIYu.r6QmBw6QMjdaZAoQE5PiTPKIhtCDASG', 'super_admin', 'active', '2026-06-27 06:46:09', '2026-06-27 07:46:58');

-- --------------------------------------------------------

--
-- Table structure for table `banners`
--

CREATE TABLE `banners` (
  `id` int(11) NOT NULL,
  `title` varchar(255) DEFAULT NULL,
  `subtitle` text DEFAULT NULL,
  `image_path` varchar(255) NOT NULL,
  `button_text` varchar(100) DEFAULT NULL,
  `button_link` varchar(255) DEFAULT NULL,
  `display_order` int(11) DEFAULT 0,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `banners`
--

INSERT INTO `banners` (`id`, `title`, `subtitle`, `image_path`, `button_text`, `button_link`, `display_order`, `status`, `created_at`, `updated_at`) VALUES
(1, NULL, NULL, '/uploads/banners/banner_one.png', NULL, NULL, NULL, 'active', '2026-06-27 21:33:17', '2026-07-05 08:51:32'),
(2, 'Lightning Fast Delivery', 'Get your favorites delivered same-day anywhere in Indira Nagar', '/uploads/banners/banner_two.png', 'View Delivery Info', '#delivery', 1, 'active', '2026-06-27 21:33:17', '2026-08-02 15:40:34'),
(3, '100% Authentic Products', 'Curated vaping devices and premium e-liquids from top brands', '/uploads/banners/banner_three.png', 'Explore Brands', '/products', 2, 'active', '2026-06-27 21:33:17', '2026-06-27 21:33:17'),
(4, 'Huge Selection of Flavors', 'Hundreds of unique flavors and top-tier pod systems in stock', '/uploads/banners/banner_four.png', 'Discover Flavors', '/products', 3, 'active', '2026-06-27 21:33:17', '2026-06-27 21:33:17');

-- --------------------------------------------------------

--
-- Table structure for table `categories`
--

CREATE TABLE `categories` (
  `id` int(11) NOT NULL,
  `category_name` varchar(100) NOT NULL,
  `slug` varchar(150) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `categories`
--

INSERT INTO `categories` (`id`, `category_name`, `slug`, `description`, `status`, `created_at`, `updated_at`) VALUES
(2, 'Disposable vapes', 'disposable-vapes', 'Use and throw', 'active', '2026-06-27 10:03:32', '2026-06-27 10:28:24'),
(3, 'NICTOIN', 'nictoin', 'ADFBGSUFGUSGAFNI', 'active', '2026-06-27 13:14:04', '2026-06-27 13:14:04'),
(4, 'POWERUPS', 'powerups', 'AF9S8AHF9WEF', 'active', '2026-06-27 13:14:20', '2026-06-27 13:14:20'),
(5, 'BULLBITE', 'bullbite', 'FDNGWFGOCEW 8N 98WETGEW', 'active', '2026-06-27 13:14:40', '2026-06-27 13:14:40'),
(6, 'Pod Systems', 'pod-systems', 'Compact and easy to use pod devices.', 'active', '2026-06-28 06:39:48', '2026-06-28 06:39:48'),
(7, 'E-Liquids', 'e-liquids', 'Premium e-liquids and nic salts.', 'active', '2026-06-28 06:39:48', '2026-06-28 06:39:48'),
(8, 'Vape Mods', 'vape-mods', 'Advanced sub-ohm vaping mods.', 'active', '2026-06-28 06:39:48', '2026-06-28 06:39:48'),
(9, 'Accessories', 'accessories', 'Batteries, chargers, and cases.', 'active', '2026-06-28 06:39:48', '2026-06-28 06:39:48'),
(10, 'Coils & Tanks', 'coils-and-tanks', 'Replacement coils and high-quality tanks.', 'active', '2026-06-28 06:39:48', '2026-06-28 06:39:48');

-- --------------------------------------------------------

--
-- Table structure for table `contact_information`
--

CREATE TABLE `contact_information` (
  `id` int(11) NOT NULL,
  `company_name` varchar(255) DEFAULT NULL,
  `phone` varchar(30) DEFAULT NULL,
  `whatsapp` varchar(30) DEFAULT NULL,
  `email` varchar(150) DEFAULT NULL,
  `address` text DEFAULT NULL,
  `google_map_link` text DEFAULT NULL,
  `facebook` varchar(255) DEFAULT NULL,
  `instagram` varchar(255) DEFAULT NULL,
  `twitter` varchar(255) DEFAULT NULL,
  `youtube` varchar(255) DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `logo_image` varchar(255) DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `contact_information`
--

INSERT INTO `contact_information` (`id`, `company_name`, `phone`, `whatsapp`, `email`, `address`, `google_map_link`, `facebook`, `instagram`, `twitter`, `youtube`, `updated_at`, `logo_image`) VALUES
(1, 'Vape Shop Koramangala', '6362854192', '6362854192', 'orders@vapestore.com', '80 Feet Road, 4th Block, Koramangala, Indira Nagar, Karnataka 560034', '', '', '', '', '', '2026-08-02 15:33:54', '');

-- --------------------------------------------------------

--
-- Table structure for table `delivery_areas`
--

CREATE TABLE `delivery_areas` (
  `id` int(11) NOT NULL,
  `main_area` varchar(255) NOT NULL,
  `sub_areas` text NOT NULL,
  `link_text` varchar(100) DEFAULT 'Vape delivery here →',
  `link_url` varchar(255) DEFAULT '/#products',
  `display_order` int(11) DEFAULT 0,
  `status` varchar(20) DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `delivery_areas`
--

INSERT INTO `delivery_areas` (`id`, `main_area`, `sub_areas`, `link_text`, `link_url`, `display_order`, `status`, `created_at`, `updated_at`) VALUES
(1, 'HAL 2nd Stage & Defence Colony', '100 Feet Road, 12th Main, 100ft Rd, Doopanahalli', 'Shop now', '/#products', 1, 'active', '2026-08-02 15:42:28', '2026-08-02 15:42:28'),
(2, 'HAL 3rd Stage & Jeevan Bheema Nagar', 'New Tippasandra, Geethanjali Layout, Kodihalli', 'Shop now', '/#products', 2, 'active', '2026-08-02 15:42:28', '2026-08-02 15:42:28'),
(3, 'Domlur & EGL', 'Domlur Layout, Amarjyothi Layout, Wind Tunnel Road', 'Shop now', '/#products', 3, 'active', '2026-08-02 15:42:28', '2026-08-02 15:42:28'),
(4, 'Ulsoor & Cambridge Layout', 'Gupta Layout, Jogupalya, MG Road', 'Shop now', '/#products', 4, 'active', '2026-08-02 15:42:28', '2026-08-02 15:42:28'),
(5, 'CV Raman Nagar', 'Kaggadasapura, GM Palya, Malleshpalya', 'Shop now', '/#products', 5, 'active', '2026-08-02 15:42:28', '2026-08-02 15:42:28'),
(6, 'Koramangala & HSR Layout', '1st Block, 4th Block, HSR Layout Sectors', 'Shop now', '/#products', 6, 'active', '2026-08-02 15:42:28', '2026-08-02 15:42:28');

-- --------------------------------------------------------

--
-- Table structure for table `enquiries`
--

CREATE TABLE `enquiries` (
  `id` int(11) NOT NULL,
  `name` varchar(150) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `mobile` varchar(20) DEFAULT NULL,
  `message` text DEFAULT NULL,
  `enquiry_type` enum('whatsapp','contact_form') DEFAULT 'contact_form',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `flavours`
--

CREATE TABLE `flavours` (
  `id` int(11) NOT NULL,
  `flavour_name` varchar(100) NOT NULL,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `footer_settings`
--

CREATE TABLE `footer_settings` (
  `id` int(11) NOT NULL,
  `footer_text` text DEFAULT NULL,
  `copyright_text` varchar(255) DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `footer_logo_text` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `footer_settings`
--

INSERT INTO `footer_settings` (`id`, `footer_text`, `copyright_text`, `updated_at`, `footer_logo_text`) VALUES
(1, 'Looking for premium vape devices in Indira Nagar? Vape Shop Indira Nagar offers a wide range of disposable devices, pod systems, premium accessories, and popular device collections with fast 45-minute express delivery across Indira Nagar & nearby Indira Nagar areas. Serving 1st to 8th Block, NGV, HSR Layout, BTM Layout, Indiranagar, Jayanagar, and surrounding hubs. Enjoy quick ordering, 100% authentic products, and fast doorstep delivery.', '© {year} Vape Shop Koramangala Store. All rights reserved.', '2026-08-02 15:33:54', 'Disposable Vape & Pod Devices 45-Min Express Delivery in Koramangala, Indira Nagar.');

-- --------------------------------------------------------

--
-- Table structure for table `marquee_products`
--

CREATE TABLE `marquee_products` (
  `id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `display_order` int(11) DEFAULT 0,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `orders`
--

CREATE TABLE `orders` (
  `id` int(11) NOT NULL,
  `customer_name` varchar(150) NOT NULL,
  `mobile_number` varchar(20) NOT NULL,
  `address` text NOT NULL,
  `pin_code` varchar(10) DEFAULT NULL,
  `latitude` varchar(50) DEFAULT NULL,
  `longitude` varchar(50) DEFAULT NULL,
  `total_items` int(11) DEFAULT 0,
  `grand_total` decimal(10,2) DEFAULT 0.00,
  `order_status` enum('pending','contacted','completed','cancelled') DEFAULT 'pending',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `whatsapp_sent` enum('yes','no') DEFAULT 'no'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `orders`
--

INSERT INTO `orders` (`id`, `customer_name`, `mobile_number`, `address`, `pin_code`, `latitude`, `longitude`, `total_items`, `grand_total`, `order_status`, `created_at`, `updated_at`, `whatsapp_sent`) VALUES
(1, 'BM NIZAMUDDIN', '2837284782', 'bantwal', '574211', NULL, NULL, 1, 500.00, 'pending', '2026-06-27 19:38:15', '2026-06-27 19:38:15', 'no'),
(2, 'BM NIZAMUDDIN', '2837284782', 'bantwal', '574211', NULL, NULL, 1, 500.00, 'pending', '2026-06-27 19:38:17', '2026-06-27 19:38:17', 'no'),
(3, 'BM NIZAMUDDIN', '9800000004', 'urgnh jakopl', '574211', NULL, NULL, 1, 500.00, 'pending', '2026-06-27 19:38:33', '2026-06-27 19:38:33', 'no'),
(4, 'BM NIZAMUDDIN', '9800000004', 'urgnh jakopl', '574211', NULL, NULL, 1, 500.00, 'pending', '2026-06-27 19:39:06', '2026-06-27 19:39:06', 'no'),
(5, 'BM NIZAMUDDIN', '9800000004', 'urgnh jakopl', '574211', NULL, NULL, 1, 500.00, 'completed', '2026-06-27 19:39:20', '2026-06-27 20:00:29', 'no'),
(6, 'BM NIZAMUDDIN', '9800000004', 'urgnh jakopl', '574211', NULL, NULL, 1, 500.00, 'completed', '2026-06-27 19:41:49', '2026-06-27 19:59:53', 'no'),
(7, 'nnizam', '2992848258', 'Bantval, Karnataka', '', '12.890581', '75.04104168597078', 1, 500.00, 'completed', '2026-06-27 19:42:40', '2026-06-27 20:00:20', 'no'),
(8, 'mazin bro', '9800000004', 'Bantval, Karnataka', '', '12.890581000000001', '75.04104102317596', 3, 1500.00, 'completed', '2026-06-27 21:00:56', '2026-06-27 21:05:17', 'no'),
(9, 'mizuu', '4290852865', 'urdangadi', '574211', NULL, NULL, 3, 1098.00, 'cancelled', '2026-06-27 21:09:24', '2026-06-27 21:10:27', 'no'),
(10, 'brother', '1282989211', 'Bantval, Karnataka', '', '12.890581000000001', '75.04104008934847', 1, 3445.00, 'completed', '2026-06-27 21:12:38', '2026-06-27 21:13:17', 'no'),
(11, 'maxi', '3189212412', 'Bantval, Karnataka', '', '12.89058043330627', '75.04102784226068', 14, 47922.00, 'completed', '2026-06-27 21:17:06', '2026-06-27 21:17:17', 'no'),
(12, 'BM NIZAMUDDIN', '9800000004', 'urgnh jakopl', '574218', NULL, NULL, 6, 2196.00, 'pending', '2026-06-27 21:18:03', '2026-06-27 21:18:40', 'no'),
(13, 'NIZAM', '3498326238', '', '', NULL, NULL, 1, 500.00, 'pending', '2026-06-28 09:50:32', '2026-06-28 09:50:32', 'no'),
(14, 'nizam', '9023789236', 'Bantval, Karnataka', '', '12.890578724546172', '75.0410308775651', 1, 500.00, 'pending', '2026-06-28 09:51:14', '2026-06-28 09:51:14', 'no'),
(15, 'nizamm', '2784872548', '', '', NULL, NULL, 1, 3200.00, 'pending', '2026-06-28 09:51:50', '2026-06-28 09:51:50', 'no'),
(16, 'nizam', '2846873247', '', '', NULL, NULL, 1, 3423.00, 'pending', '2026-06-28 09:55:05', '2026-06-28 09:55:05', 'no'),
(17, 'BM NIZAMUDDIN', '9800000004', 'Bantval, Karnataka', '', '12.890581', '75.04104168597078', 1, 800.00, 'pending', '2026-06-28 09:55:45', '2026-06-28 09:55:45', 'no'),
(18, 'nizam', '2846873247', '', '', NULL, NULL, 1, 500.00, 'pending', '2026-06-28 09:56:10', '2026-06-28 09:56:10', 'no'),
(19, 'nizam', '2846873247', 'Bantval, Karnataka', '', '12.890579087244982', '75.0410356789683', 1, 500.00, 'pending', '2026-06-28 09:58:32', '2026-06-28 09:58:32', 'no'),
(20, 'nizam', '8932896492', 'Bantval, Karnataka', '', '12.890581000000001', '75.04104286509867', 1, 3445.00, 'pending', '2026-06-28 12:45:21', '2026-06-28 12:45:21', 'no'),
(21, 'Sheik Shahid', '9901361244', 'Bantval, Karnataka', '', '12.76463060207582', '75.10389763875452', 2, 6400.00, 'pending', '2026-06-28 16:05:14', '2026-06-28 16:05:14', 'no'),
(22, 'Sheik Shahid', '9901361244', 'Bantval, Karnataka', '', '12.764628065473387', '75.10389595799968', 2, 6890.00, 'pending', '2026-07-02 16:22:46', '2026-07-02 16:22:46', 'no'),
(23, 'Sheik Shahid', '7879064589', 'Bantval, Karnataka', '', '12.764628065473387', '75.10389595799968', 1, 3200.00, 'pending', '2026-07-02 16:23:34', '2026-07-02 16:23:34', 'no'),
(24, 'Sheik Shahid', '9901361244', 'Vittal Karnataka', '574243', NULL, NULL, 1, 500.00, 'pending', '2026-07-02 17:43:19', '2026-07-02 17:43:19', 'no'),
(25, 'Sheik Shahid', '9901361244', 'Bantval, Karnataka', '', '12.764607', '75.103882', 2, 732.00, 'pending', '2026-07-02 17:47:49', '2026-07-02 17:47:49', 'no'),
(26, 'Sheik Shahid', '9901361244', 'Bantval, Karnataka', '', '12.764607', '75.103882', 2, 866.00, 'pending', '2026-07-02 17:49:40', '2026-07-02 17:49:40', 'no'),
(27, 'Anita Menon', '9901361244', 'Bantval, Karnataka', '', '12.764607', '75.103882', 1, 3200.00, 'pending', '2026-07-02 17:51:31', '2026-07-02 17:51:31', 'no'),
(28, 'Sheik', '7879064589', 'Bantval, Karnataka', '', '12.764607', '75.103882', 1, 500.00, 'pending', '2026-07-02 17:53:42', '2026-07-02 17:53:42', 'no'),
(29, 'Anita Menon', '9876543211', 'Bantval, Karnataka', '', '12.764607', '75.103882', 1, 3445.00, 'pending', '2026-07-02 17:54:39', '2026-07-02 17:54:39', 'no'),
(30, 'Sheik', '7879064589', 'Bantval, Karnataka', '', '12.764607', '75.103882', 1, 500.00, 'pending', '2026-07-02 17:57:55', '2026-07-02 17:57:55', 'no'),
(31, 'Sheik Shahid', '9901361244', 'Bantval, Karnataka', '', '12.764607', '75.103882', 4, 1464.00, 'pending', '2026-07-02 17:59:01', '2026-07-02 17:59:01', 'no'),
(32, 'Sheikh Shahid', '9448315844', 'Ponnot\nSample', '574243', NULL, NULL, 1, 2999.00, 'pending', '2026-07-02 18:47:11', '2026-07-02 18:47:11', 'no'),
(33, 'Sheikh Shahid', '9448315844', 'Ponnot\nSample', '574243', NULL, NULL, 1, 500.00, 'pending', '2026-07-02 18:47:49', '2026-07-02 18:47:49', 'no'),
(34, 'Near Mescom', '9448315844', 'Ponnot', '583432', NULL, NULL, 1, 3423.00, 'pending', '2026-07-02 18:48:55', '2026-07-02 18:48:55', 'no'),
(35, 'Near Mescom', '9448315844', 'Bantval, Karnataka', '574243', '12.7651507', '75.1039833', 1, 366.00, 'pending', '2026-07-02 18:51:57', '2026-07-02 18:51:57', 'no'),
(36, 'Sheik', '9876543211', 'Vitla, Bantwal taluk, Dakshina Kannada, Karnataka, 574243, India', '574243', '12.764628065473387', '75.10389595799968', 1, 500.00, 'pending', '2026-07-03 08:05:09', '2026-07-03 08:05:09', 'no'),
(37, 'Sheik Shahid', '9876543211', 'Vitla, Bantwal taluk, Dakshina Kannada, Karnataka, 574243, India', '574243', '12.764628065473387', '75.10389595799968', 2, 3945.00, 'pending', '2026-07-03 08:07:19', '2026-07-03 08:07:19', 'no'),
(38, 'Sheik Shahid', '9901361244', 'Vitla, Bantwal taluk, Dakshina Kannada, Karnataka, 574243, India', '574243', '12.764628065473387', '75.10389595799968', 8, 15389.00, 'pending', '2026-07-03 10:46:19', '2026-07-03 10:46:19', 'no'),
(39, 'nizam', '8932896492', 'Kaikunje, Bantwal, Bantwal taluk, Dakshina Kannada, Karnataka, 574211, India', '574211', '12.890581000000001', '75.04104102317596', 3, 1098.00, 'pending', '2026-07-05 08:34:21', '2026-07-05 08:34:21', 'no'),
(40, 'Test', '9562378492', 'Test', '574218', NULL, NULL, 1, 3200.00, 'pending', '2026-07-05 10:29:41', '2026-07-05 10:29:41', 'no'),
(41, 'rave', '9800000004', 'Kaikunje, Bantwal, Bantwal taluk, Dakshina Kannada, Karnataka, 574211, India', '574211', '12.890581', '75.041061', 1, 500.00, 'pending', '2026-07-25 17:57:54', '2026-07-25 17:57:54', 'no'),
(42, 'rave', '9800000004', 'Kaikunje, Bantwal, Bantwal taluk, Dakshina Kannada, Karnataka, 574211, India', '574211', '12.890581000000003', '75.0410429198612', 1, 500.00, 'pending', '2026-07-30 18:43:29', '2026-07-30 18:43:29', 'no'),
(43, 'brawlstar', '9800000004', 'Kaikunje, Bantwal, Bantwal taluk, Dakshina Kannada, Karnataka, 574211, India', '574211', '12.890581000000001', '75.04104693619898', 1, 3423.00, 'completed', '2026-08-01 05:40:04', '2026-08-01 05:44:40', 'no'),
(44, 'brawlstar', '9800000004', 'Kaikunje, Bantwal, Bantwal taluk, Dakshina Kannada, Karnataka, 574211, India', '574211', '12.890581000000001', '75.04104693619898', 1, 2999.00, 'pending', '2026-08-01 05:50:17', '2026-08-01 05:50:17', 'no'),
(45, 'brawlstar', '9800000004', 'Kaikunje, Bantwal, Bantwal taluk, Dakshina Kannada, Karnataka, 574211, India', '574211', '12.890581000000001', '75.041042', 1, 366.00, 'pending', '2026-08-01 06:11:28', '2026-08-01 06:11:28', 'no'),
(46, 'brawlstar', '9800000004', 'Kaikunje, Bantwal, Bantwal taluk, Dakshina Kannada, Karnataka, 574211, India', '574211', '12.890581000000001', '75.041023', 2, 1000.00, 'pending', '2026-08-01 12:03:23', '2026-08-01 12:03:23', 'no'),
(47, 'BM NIZAMUDDIN', '9800000004', 'Kaikunje, Bantwal, Bantwal taluk, Dakshina Kannada, Karnataka, 574211, India', '574211', '12.890581000000001', '75.041023', 1, 500.00, 'pending', '2026-08-01 17:12:52', '2026-08-01 17:12:52', 'no'),
(48, 'BM NIZAMUDDIN', '9800000004', 'Kaikunje, Bantwal, Bantwal taluk, Dakshina Kannada, Karnataka, 574211, India', '574211', '12.890581000000001', '75.04104693619898', 11, 13200.00, 'completed', '2026-08-02 09:15:01', '2026-08-02 09:26:34', 'no'),
(49, 'BM NIZAMUDDIN', '9800000004', 'Kaikunje, Bantwal, Bantwal taluk, Dakshina Kannada, Karnataka, 574211, India', '574211', '12.890581000000001', '75.04103867296138', 2, 2400.00, 'completed', '2026-08-02 09:30:21', '2026-08-02 09:31:11', 'no'),
(50, 'nizam', '8723478235', 'Kaikunje, Bantwal, Bantwal taluk, Dakshina Kannada, Karnataka, 574211, India', '574211', '12.890581000000001', '75.041023', 1, 2999.00, 'completed', '2026-08-02 15:47:57', '2026-08-02 15:48:57', 'no');

-- --------------------------------------------------------

--
-- Table structure for table `order_items`
--

CREATE TABLE `order_items` (
  `id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `flavour_name` varchar(100) DEFAULT NULL,
  `flavour_id` int(11) DEFAULT NULL,
  `quantity` int(11) DEFAULT 1,
  `unit_price` decimal(10,2) DEFAULT 0.00,
  `total_price` decimal(10,2) DEFAULT 0.00,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `order_items`
--

INSERT INTO `order_items` (`id`, `order_id`, `product_id`, `flavour_name`, `flavour_id`, `quantity`, `unit_price`, `total_price`, `created_at`) VALUES
(1, 6, 5, '', NULL, 1, 500.00, 500.00, '2026-06-27 19:41:49'),
(2, 7, 5, '', NULL, 1, 500.00, 500.00, '2026-06-27 19:42:40'),
(3, 8, 5, '', NULL, 3, 500.00, 1500.00, '2026-06-27 21:00:56'),
(4, 9, 6, 'mint', NULL, 3, 366.00, 1098.00, '2026-06-27 21:09:24'),
(5, 10, 3, '', NULL, 1, 3445.00, 3445.00, '2026-06-27 21:12:38'),
(6, 11, 4, 'hulk green', NULL, 14, 3423.00, 47922.00, '2026-06-27 21:17:06'),
(7, 12, 6, 'mint', NULL, 6, 366.00, 2196.00, '2026-06-27 21:18:03'),
(8, 13, 5, '', NULL, 1, 500.00, 500.00, '2026-06-28 09:50:32'),
(9, 14, 5, '', NULL, 1, 500.00, 500.00, '2026-06-28 09:51:14'),
(10, 15, 11, '', NULL, 1, 3200.00, 3200.00, '2026-06-28 09:51:50'),
(11, 16, 4, 'hulk green', NULL, 1, 3423.00, 3423.00, '2026-06-28 09:55:05'),
(12, 17, 7, '', NULL, 1, 800.00, 800.00, '2026-06-28 09:55:45'),
(13, 18, 5, '', NULL, 1, 500.00, 500.00, '2026-06-28 09:56:10'),
(14, 19, 12, '', NULL, 1, 500.00, 500.00, '2026-06-28 09:58:32'),
(15, 20, 3, '', NULL, 1, 3445.00, 3445.00, '2026-06-28 12:45:21'),
(16, 21, 11, '', NULL, 2, 3200.00, 6400.00, '2026-06-28 16:05:14'),
(17, 22, 3, '', NULL, 2, 3445.00, 6890.00, '2026-07-02 16:22:46'),
(18, 23, 11, '', NULL, 1, 3200.00, 3200.00, '2026-07-02 16:23:34'),
(19, 24, 5, '', NULL, 1, 500.00, 500.00, '2026-07-02 17:43:19'),
(20, 25, 6, 'mango ice', NULL, 1, 366.00, 366.00, '2026-07-02 17:47:49'),
(21, 25, 6, 'mint', NULL, 1, 366.00, 366.00, '2026-07-02 17:47:49'),
(22, 26, 5, '', NULL, 1, 500.00, 500.00, '2026-07-02 17:49:40'),
(23, 26, 6, 'mango ice', NULL, 1, 366.00, 366.00, '2026-07-02 17:49:40'),
(24, 27, 11, '', NULL, 1, 3200.00, 3200.00, '2026-07-02 17:51:31'),
(25, 28, 5, '', NULL, 1, 500.00, 500.00, '2026-07-02 17:53:42'),
(26, 29, 3, '', NULL, 1, 3445.00, 3445.00, '2026-07-02 17:54:39'),
(27, 30, 5, '', NULL, 1, 500.00, 500.00, '2026-07-02 17:57:55'),
(28, 31, 6, 'mango ice', NULL, 2, 366.00, 732.00, '2026-07-02 17:59:01'),
(29, 31, 6, 'mint', NULL, 2, 366.00, 732.00, '2026-07-02 17:59:01'),
(30, 32, 13, '', NULL, 1, 2999.00, 2999.00, '2026-07-02 18:47:11'),
(31, 33, 5, '', NULL, 1, 500.00, 500.00, '2026-07-02 18:47:49'),
(32, 34, 4, 'hulk green', NULL, 1, 3423.00, 3423.00, '2026-07-02 18:48:55'),
(33, 35, 6, 'mango ice', NULL, 1, 366.00, 366.00, '2026-07-02 18:51:57'),
(34, 36, 5, '', NULL, 1, 500.00, 500.00, '2026-07-03 08:05:09'),
(35, 37, 5, '', NULL, 1, 500.00, 500.00, '2026-07-03 08:07:19'),
(36, 37, 3, '', NULL, 1, 3445.00, 3445.00, '2026-07-03 08:07:19'),
(37, 38, 5, '', NULL, 1, 500.00, 500.00, '2026-07-03 10:46:19'),
(38, 38, 7, '', NULL, 2, 800.00, 1600.00, '2026-07-03 10:46:19'),
(39, 38, 8, '', NULL, 2, 1200.00, 2400.00, '2026-07-03 10:46:19'),
(40, 38, 3, '', NULL, 2, 3445.00, 6890.00, '2026-07-03 10:46:19'),
(41, 38, 1, '', NULL, 1, 3999.00, 3999.00, '2026-07-03 10:46:19'),
(42, 39, 6, 'mint', NULL, 3, 366.00, 1098.00, '2026-07-05 08:34:21'),
(43, 40, 11, '', NULL, 1, 3200.00, 3200.00, '2026-07-05 10:29:41'),
(44, 41, 5, '', NULL, 1, 500.00, 500.00, '2026-07-25 17:57:54'),
(45, 42, 12, '', NULL, 1, 500.00, 500.00, '2026-07-30 18:43:29'),
(46, 43, 4, 'hulk green', NULL, 1, 3423.00, 3423.00, '2026-08-01 05:40:04'),
(47, 44, 13, '', NULL, 1, 2999.00, 2999.00, '2026-08-01 05:50:17'),
(48, 45, 6, 'mint', NULL, 1, 366.00, 366.00, '2026-08-01 06:11:28'),
(49, 46, 5, '', NULL, 2, 500.00, 1000.00, '2026-08-01 12:03:23'),
(50, 47, 5, '', NULL, 1, 500.00, 500.00, '2026-08-01 17:12:52'),
(51, 48, 8, 'ice', NULL, 7, 1200.00, 8400.00, '2026-08-02 09:15:01'),
(52, 48, 8, 'coco', NULL, 4, 1200.00, 4800.00, '2026-08-02 09:15:01'),
(53, 49, 8, 'ice', NULL, 2, 1200.00, 2400.00, '2026-08-02 09:30:21'),
(54, 50, 13, '', NULL, 1, 2999.00, 2999.00, '2026-08-02 15:47:57');

-- --------------------------------------------------------

--
-- Table structure for table `products`
--

CREATE TABLE `products` (
  `id` int(11) NOT NULL,
  `category_id` int(11) NOT NULL,
  `primary_image` varchar(255) DEFAULT NULL,
  `product_name` varchar(255) NOT NULL,
  `slug` varchar(255) DEFAULT NULL,
  `short_description` varchar(500) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `price` decimal(10,2) DEFAULT 0.00,
  `mrp` decimal(10,2) DEFAULT 0.00,
  `stock` int(11) DEFAULT 0,
  `sales_count` int(11) DEFAULT 0,
  `featured` enum('yes','no') DEFAULT 'no',
  `seo_title` varchar(255) DEFAULT NULL,
  `seo_description` text DEFAULT NULL,
  `seo_keywords` text DEFAULT NULL,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `nicotine_strength` varchar(50) DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `products`
--

INSERT INTO `products` (`id`, `category_id`, `primary_image`, `product_name`, `slug`, `short_description`, `description`, `price`, `mrp`, `stock`, `sales_count`, `featured`, `seo_title`, `seo_description`, `seo_keywords`, `status`, `created_at`, `updated_at`, `nicotine_strength`) VALUES
(1, 2, '/uploads/products/1782560994501-64885393.png', 'Buy Elfbar Sobo 40000 Puffs Koramangala | 45-Minute Delivery', 'buy-elfbar-sobo-40000-puffs-koramangala-45-minute-delivery', 'If you’ve been searching for the best disposable vape in Hyderabad with the fastest delivery, your search ends here. The Elfbar Sobo 40,000 Puffs is now available for express delivery across Hyderabad — from Jubilee Hills to Gachibowli, Banjara Hills to Hitech City, Kondapur to Kukatpally — delivered in 45 minutes or less, right to your doorstep.', 'If you’ve been searching for the best disposable vape in Hyderabad with the fastest delivery, your search ends here. The Elfbar Sobo 40,000 Puffs is now available for express delivery across Hyderabad — from Jubilee Hills to Gachibowli, Banjara Hills to Hitech City, Kondapur to Kukatpally — delivered in 45 minutes or less, right to your doorstep.\n\nWe are Hyderabad’s most trusted vape delivery service. No waiting days for courier. No driving to a store. Just order online or WhatsApp us, and your Elfbar Sobo 40K is with you in under an hour.\n\nWhat Makes the Elfbar Sobo 40,000 Puffs the Best Disposable Vape in Hyderabad?\n\nThe disposable vape market in India has exploded, and with so many devices available, it can be hard to know which one is actually worth your money. The Elfbar Sobo 40K answers that question immediately. It combines the highest puff count available in any disposable vape right now with a rechargeable battery, a smart full-screen display, and flavour quality that stays consistent from the very first puff all the way to the last.\n\nMost disposable vapes available in Hyderabad give you 5,000 to 10,000 puffs and call it premium. The Elfbar Sobo delivers 40,000 puffs — making it last weeks, not days. For regular vapers in Hyderabad who go through devices quickly, this is a complete game changer in terms of value and convenience.\n\nElfbar Sobo 40K — Full Technical Specifications\n\n\n\n|Feature |Specification |\n|-----------------|--------------------------|\n|Puff Count |Up to 40,000 Puffs |\n|E-Liquid Capacity|28ml |\n|Battery Capacity |1000mAh Integrated |\n|Charging Port |Type-C Fast Charging |\n|Nicotine Strength|50mg/ml (5%) |\n|Coil Type |Mesh Coil |\n|Display |Smart LED Full Screen |\n|Operation |Draw-Activated (No Button)|\n|Device Type |Rechargeable Disposable |\n\nSmart Display — Always Know Your Battery and Juice Level\n\nOne of the most frustrating things about cheap disposable vapes is not knowing when they’re going to run out. You take a puff, it tastes burnt, and suddenly your device is dead — and you have no idea how much e-liquid was left.\n\nThe Elfbar Sobo 40K completely solves this with its smart LED full-screen display. At a glance, you can see your exact battery percentage and remaining e-liquid level in real time. No guessing. No surprises. You’ll always know exactly how much life your device has left, so you can plan your recharge or reorder well in advance.\n\nMesh Coil Technology — Flavour That Never Fades\n\nThe Elfbar Sobo 40K uses an advanced mesh coil that distributes heat evenly across the entire coil surface. What this means for you is richer, fuller flavour with every single puff — and no burnt taste even after thousands of puffs. The mesh coil design is specifically engineered to maintain consistent vapour production and flavour intensity all the way through the device’s 40,000-puff lifespan.\n\nWhether you prefer fruity, icy, menthol, or tobacco flavours, the Sobo 40K’s coil brings out the full depth of every flavour profile.\n\n1000mAh Rechargeable Battery with Type-C Fast Charging\n\nUnlike older disposable vapes that die mid-session with no option to recharge, the Elfbar Sobo 40K comes with a 1000mAh built-in rechargeable battery and a Type-C charging port. This means even on your heaviest vaping days, you can simply plug in for a short while and get right back to it.\n\nThe Type-C fast charging support means you’re not waiting around for hours — a quick top-up and you’re back to full power within minutes.\n\n45-Minute Delivery Across All of Hyderabad\n\nThis is what sets us apart from every other vape seller in Hyderabad.', 3999.00, 0.00, 50, 0, 'no', '', '', '', 'active', '2026-06-27 10:20:07', '2026-08-01 10:36:49', ''),
(2, 2, '/uploads/products/1782562113407-351436164.png', 'Buy Yuoto Pop 5000 Puffs Koramangala | 45-Minute Delivery', 'buy-yuoto-pop-5000-puffs-koramangala-45-minute-delivery', 'A smooth fruit mix.', 'Enjoy the vibrant flavours of Vape Pop 5000, bringing you a consistent blast of juicy fruits with every puff. Features a 500mAh rechargeable battery and premium mesh coil.', 2000.00, 4000.00, 10, 1, 'yes', 'Buy Yuoto Pop 5000 Puffs Hyderabad | 45-Minute Delivery', '', '', 'active', '2026-06-27 10:39:43', '2026-08-01 10:36:49', ''),
(3, 2, '/uploads/products/1782566029103-192445762.jpg', 'Buy IGET Pro 8000 Puffs Koramangala | 45-Minute Delivery', 'buy-iget-pro-8000-puffs-koramangala-45-minute-delivery', 'Intense flavor profile.', 'The Zagbro Pro 8000 offers an intense and refreshing flavour profile. Its ergonomic design and long-lasting battery make it perfect for on-the-go vaping.', 3445.00, 24234.00, 33, 4, 'no', 'Buy IGET Pro 8000 Puffs Hyderabad | 45-Minute Delivery', '', '', 'active', '2026-06-27 13:13:49', '2026-08-01 10:36:49', ''),
(4, 3, '/uploads/products/1782566152121-193869175.png', 'Buy Tugboat Mega 4500 Puffs Koramangala | 45-Minute Delivery', 'buy-tugboat-mega-4500-puffs-koramangala-45-minute-delivery', 'Classic robust flavor.', 'Jack 4500 delivers a classic and robust taste for those who prefer strong throat hits. Reliable performance and sleek design.', 3423.00, 141434.00, 34, 49, 'no', 'Buy Tugboat Mega 4500 Puffs Hyderabad | 45-Minute Delivery', '', '', 'active', '2026-06-27 13:15:52', '2026-08-01 10:36:49', ''),
(5, 5, '/uploads/products/1782566189676-148951815.jpg', 'Buy Elfbar BC10000 Puffs Koramangala | 45-Minute Delivery', 'buy-elfbar-bc10000-puffs-koramangala-45-minute-delivery', 'Premium high capacity.', 'King Leo 10000 is a premium device offering unmatched capacity and flavor. Enjoy days of vaping with a smart display and fast charging.', 500.00, 789.00, 62, 7, 'yes', 'Buy Elfbar BC10000 Puffs Hyderabad | 45-Minute Delivery', '', '', 'active', '2026-06-27 13:16:29', '2026-08-01 10:36:49', ''),
(6, 4, '/uploads/products/1782570091629-126386840.png', 'Buy KK Energy Mini 1200 Puffs Koramangala | 45-Minute Delivery', 'buy-kk-energy-mini-1200-puffs-koramangala-45-minute-delivery', 'Compact and discreet.', 'Meo Mouse Mini is a compact, pocket-friendly vape that packs a punch. Ideal for a quick session with consistent flavor output.', 366.00, 500.00, 10, 8, 'yes', 'Buy KK Energy Mini 1200 Puffs Hyderabad | 45-Minute Delivery', '', '', 'active', '2026-06-27 14:21:31', '2026-08-01 10:36:49', ''),
(7, 2, '/uploads/products/1782628884011-403923895.png', 'Buy SKE Crystal Bar 600 Puffs Koramangala | 45-Minute Delivery', 'buy-ske-crystal-bar-600-puffs-koramangala-45-minute-delivery', 'Sleek crystal design.', '1. Fruity Blast 🍓🍍\r\n\r\n🍓 Fruity Blast\r\nExperience a burst of juicy strawberries, ripe mangoes, and tropical pineapple in every puff. 🌴✨ Smooth, refreshing, and packed with vibrant flavor for an unforgettable vaping experience.\r\n\r\n2. Cool Mint ❄️🌿\r\n\r\n❄️ Cool Mint\r\nEnjoy the crisp freshness of icy mint that delivers a clean, cooling sensation with every inhale. 🌬️ Perfect for those who love a refreshing all-day vape.\r\n\r\n3. Blueberry Ice 🫐🧊\r\n\r\n🫐 Blueberry Ice\r\nA delicious blend of sweet blueberries finished with a chilling icy kick. 🧊💨 Rich flavor meets refreshing coolness in every puff.', 800.00, 1000.00, 50, 0, 'no', 'Buy SKE Crystal Bar 600 Puffs Hyderabad | 45-Minute Delivery', NULL, NULL, 'active', '2026-06-28 06:26:05', '2026-08-01 17:06:16', ''),
(8, 2, '/uploads/products/1782628874744-622311176.png', 'Buy Air Bar Lux 1000 Puffs Koramangala | 45-Minute Delivery', 'buy-air-bar-lux-1000-puffs-koramangala-45-minute-delivery', 'Luxury vaping experience.', 'Upgraded mouthpiece and increased battery capacity for a luxurious vaping experience.', 1200.00, 1500.00, 50, 13, 'no', 'Buy Air Bar Lux 1000 Puffs Hyderabad | 45-Minute Delivery', NULL, NULL, 'active', '2026-06-28 06:26:05', '2026-08-02 09:31:11', ''),
(9, 2, '/uploads/products/generated_vape_1.png', 'Buy Vapesring Ghost Pro 3500 Puffs Koramangala | 45-Minute Delivery', 'buy-vapesring-ghost-pro-3500-puffs-koramangala-45-minute-delivery', 'Long lasting Ghost.', 'The Ghost Pro 3500 provides an exceptionally smooth draw and rich flavor for extended usage.', 2500.00, 3000.00, 50, 0, 'no', 'Buy Vapesring Ghost Pro 3500 Puffs Hyderabad | 45-Minute Delivery', NULL, NULL, 'active', '2026-06-28 06:26:05', '2026-08-01 10:36:50', ''),
(10, 2, '/uploads/products/generated_vape_0.png', 'Buy Nasty Fix 800 Puffs Koramangala | 45-Minute Delivery', 'buy-nasty-fix-800-puffs-koramangala-45-minute-delivery', 'Award-winning Nasty juice.', 'Pre-filled with Nasty Juice’s award-winning flavors, this compact device is an instant favorite.', 900.00, 1200.00, 50, 0, 'no', 'Buy Nasty Fix 800 Puffs Hyderabad | 45-Minute Delivery', NULL, NULL, 'active', '2026-06-28 06:26:05', '2026-08-01 10:36:50', ''),
(11, 2, '/uploads/products/generated_vape_2.png', 'Buy Tugboat Evo 4500 Puffs Koramangala | 45-Minute Delivery', 'buy-tugboat-evo-4500-puffs-koramangala-45-minute-delivery', 'Adjustable airflow.', 'Tugboat Evo features an adjustable airflow control so you can tailor your hit perfectly.', 3200.00, 4000.00, 50, 0, 'no', 'Buy Tugboat Evo 4500 Puffs Hyderabad | 45-Minute Delivery', NULL, NULL, 'active', '2026-06-28 06:26:06', '2026-08-01 10:36:50', ''),
(12, 4, '/uploads/products/generated_vape_1.png', 'Buy RandM Tornado 7000 Puffs Koramangala | 45-Minute Delivery', 'buy-randm-tornado-7000-puffs-koramangala-45-minute-delivery', ' Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz ', 'Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz Xyz ', 500.00, 1000.00, 37, 0, 'no', 'Buy RandM Tornado 7000 Puffs Hyderabad | 45-Minute Delivery', '', '', 'active', '2026-06-28 06:38:13', '2026-08-01 10:36:50', '7% mg'),
(13, 5, '/uploads/products/generated_vape_0.png', 'Buy Yuoto Thanos 5000 Puffs Koramangala | 45-Minute Delivery', 'buy-yuoto-thanos-5000-puffs-koramangala-45-minute-delivery', ' SUIIIISUIIIISUIIIISUIIIISUIIIISUIIII', 'SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII\r\n<br>SUIIIISUIIIISUIIIISUIIIISUIIIISUIIIISUIIII', 2999.00, 4999.00, 49, 1, 'no', 'Buy Yuoto Thanos 5000 Puffs Hyderabad | 45-Minute Delivery', '', '', 'active', '2026-06-28 06:39:11', '2026-08-02 15:48:57', '5% mg');

-- --------------------------------------------------------

--
-- Table structure for table `product_flavours`
--

CREATE TABLE `product_flavours` (
  `id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `flavour_name` varchar(255) NOT NULL,
  `stock` int(11) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `product_flavours`
--

INSERT INTO `product_flavours` (`id`, `product_id`, `flavour_name`, `stock`, `created_at`) VALUES
(6, 2, 'MANGO', 20, '2026-06-27 20:21:33'),
(7, 2, 'cheryy pop', 15, '2026-06-27 20:21:33'),
(8, 4, 'hulk green', 1, '2026-06-27 21:16:29'),
(9, 6, 'mango ice', 20, '2026-06-27 21:19:14'),
(10, 6, 'mint', 10, '2026-06-27 21:19:14'),
(20, 8, 'ice', 1, '2026-08-02 08:48:05'),
(21, 8, 'coco', 16, '2026-08-02 08:48:05'),
(22, 8, 'mojito', 12, '2026-08-02 08:48:05');

-- --------------------------------------------------------

--
-- Table structure for table `product_images`
--

CREATE TABLE `product_images` (
  `id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `image_path` varchar(255) NOT NULL,
  `display_order` int(11) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `product_images`
--

INSERT INTO `product_images` (`id`, `product_id`, `image_path`, `display_order`, `created_at`) VALUES
(2, 2, '/uploads/products/1782556783906-663632421.jpg', 1, '2026-06-27 10:39:43'),
(3, 2, '/uploads/products/1782556783933-115586853.jpg', 2, '2026-06-27 10:39:43'),
(4, 2, '/uploads/products/1782556783946-869599988.jpg', 3, '2026-06-27 10:39:43'),
(5, 2, '/uploads/products/1782556783951-638495609.png', 4, '2026-06-27 10:39:43'),
(6, 2, '/uploads/products/1782556783952-708285544.png', 5, '2026-06-27 10:39:43'),
(12, 1, '/uploads/products/1782560994503-973747442.jpg', 1, '2026-06-27 11:49:54'),
(13, 1, '/uploads/products/1782560994524-908778311.jpg', 2, '2026-06-27 11:49:54'),
(14, 1, '/uploads/products/1782560994531-107648258.jpg', 3, '2026-06-27 11:49:54'),
(15, 1, '/uploads/products/1782560994540-875913152.png', 4, '2026-06-27 11:49:54'),
(16, 1, '/uploads/products/1782560994540-700475131.png', 5, '2026-06-27 11:49:54'),
(18, 3, '/uploads/products/1782566029140-215100653.jpg', 0, '2026-06-27 13:13:49'),
(19, 3, '/uploads/products/1782566029150-988793490.png', 1, '2026-06-27 13:13:49'),
(20, 3, '/uploads/products/1782566029151-305809560.png', 2, '2026-06-27 13:13:49'),
(21, 4, '/uploads/products/1782566152123-460785632.jpg', 0, '2026-06-27 13:15:52'),
(22, 5, '/uploads/products/1782566189719-834549609.jpg', 0, '2026-06-27 13:16:29'),
(23, 5, '/uploads/products/1782566189739-322002486.png', 1, '2026-06-27 13:16:29'),
(24, 6, '/uploads/products/1782570091632-823248700.png', 0, '2026-06-27 14:21:31'),
(25, 6, '/uploads/products/1782570091644-164359790.jpg', 1, '2026-06-27 14:21:31'),
(26, 13, '/uploads/products/1782650901260-759381970.png', 0, '2026-06-28 12:48:21'),
(27, 13, '/uploads/products/1782650901262-737179870.jpg', 1, '2026-06-28 12:48:21'),
(28, 13, '/uploads/products/1782650901273-348882098.jpg', 2, '2026-06-28 12:48:21'),
(29, 13, '/uploads/products/1782650901278-232139572.png', 3, '2026-06-28 12:48:21');

-- --------------------------------------------------------

--
-- Table structure for table `seo_settings`
--

CREATE TABLE `seo_settings` (
  `id` int(11) NOT NULL,
  `meta_title` varchar(255) DEFAULT NULL,
  `meta_description` text DEFAULT NULL,
  `meta_keywords` text DEFAULT NULL,
  `canonical_url` varchar(255) DEFAULT NULL,
  `og_title` varchar(255) DEFAULT NULL,
  `og_description` text DEFAULT NULL,
  `og_image` varchar(255) DEFAULT NULL,
  `twitter_title` varchar(255) DEFAULT NULL,
  `twitter_description` text DEFAULT NULL,
  `twitter_image` varchar(255) DEFAULT NULL,
  `robots_meta` varchar(255) DEFAULT NULL,
  `google_analytics_id` varchar(100) DEFAULT NULL,
  `google_tag_manager_id` varchar(100) DEFAULT NULL,
  `meta_pixel_id` varchar(100) DEFAULT NULL,
  `search_console_verification` text DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `settings`
--

CREATE TABLE `settings` (
  `id` int(11) NOT NULL,
  `setting_key` varchar(255) NOT NULL,
  `setting_value` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `whatsapp_settings`
--

CREATE TABLE `whatsapp_settings` (
  `id` int(11) NOT NULL,
  `business_number` varchar(20) NOT NULL,
  `default_message` text DEFAULT NULL,
  `custom_template` text DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `whatsapp_settings`
--

INSERT INTO `whatsapp_settings` (`id`, `business_number`, `default_message`, `custom_template`, `updated_at`) VALUES
(1, '6362854192', 'Hi I Am Interested in your vape', '━━━━━━━━━━━━━━━━━━━━\n🛍️ *VAPES BANGALORE | ORDER CONFIRMATION*\n━━━━━━━━━━━━━━━━━━━━\n\n*Order ID:* #[ORDER_ID]\n*Status:* New Order Received\n\n*CUSTOMER DETAILS*\n👤 *Name:* [CUSTOMER_NAME]\n\n*ORDER SUMMARY*\n──────────────\n[ITEMS]\n──────────────\n\n*TOTAL DUE:* ₹[TOTAL]\n━━━━━━━━━━━━━━━━━━━━', '2026-08-02 15:29:38');

-- --------------------------------------------------------

--
-- Table structure for table `why_choose_us`
--

CREATE TABLE `why_choose_us` (
  `id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `icon` varchar(100) DEFAULT NULL,
  `display_order` int(11) DEFAULT 0,
  `status` enum('active','inactive') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `why_choose_us`
--

INSERT INTO `why_choose_us` (`id`, `title`, `description`, `icon`, `display_order`, `status`, `created_at`) VALUES
(1, 'Premium Products', '100% authentic, curated vaping devices and premium e-liquids.', 'fas fa-crown', 0, 'active', '2026-06-27 11:23:33'),
(2, 'Fast Delivery', 'Same-day lightning fast delivery anywhere within Indira Nagar city.', 'fas fa-shipping-fast', 1, 'active', '2026-06-27 11:23:33'),
(3, 'Customer Support', 'Dedicated support on WhatsApp to help you choose the right vape.', 'fas fa-headset', 2, 'active', '2026-06-27 11:23:33'),
(4, 'Wide Selection', 'Hundreds of unique flavours and top-tier pod systems in stock.', 'fas fa-layer-group', 3, 'active', '2026-06-27 11:23:33');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `about_us`
--
ALTER TABLE `about_us`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `admins`
--
ALTER TABLE `admins`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- Indexes for table `banners`
--
ALTER TABLE `banners`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `categories`
--
ALTER TABLE `categories`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `slug` (`slug`);

--
-- Indexes for table `contact_information`
--
ALTER TABLE `contact_information`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `delivery_areas`
--
ALTER TABLE `delivery_areas`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `enquiries`
--
ALTER TABLE `enquiries`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `flavours`
--
ALTER TABLE `flavours`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `footer_settings`
--
ALTER TABLE `footer_settings`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `marquee_products`
--
ALTER TABLE `marquee_products`
  ADD PRIMARY KEY (`id`),
  ADD KEY `product_id` (`product_id`);

--
-- Indexes for table `orders`
--
ALTER TABLE `orders`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `order_items`
--
ALTER TABLE `order_items`
  ADD PRIMARY KEY (`id`),
  ADD KEY `order_id` (`order_id`),
  ADD KEY `product_id` (`product_id`),
  ADD KEY `flavour_id` (`flavour_id`);

--
-- Indexes for table `products`
--
ALTER TABLE `products`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `slug` (`slug`),
  ADD KEY `category_id` (`category_id`);

--
-- Indexes for table `product_flavours`
--
ALTER TABLE `product_flavours`
  ADD PRIMARY KEY (`id`),
  ADD KEY `product_id` (`product_id`);

--
-- Indexes for table `product_images`
--
ALTER TABLE `product_images`
  ADD PRIMARY KEY (`id`),
  ADD KEY `product_id` (`product_id`);

--
-- Indexes for table `seo_settings`
--
ALTER TABLE `seo_settings`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `settings`
--
ALTER TABLE `settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `setting_key` (`setting_key`);

--
-- Indexes for table `whatsapp_settings`
--
ALTER TABLE `whatsapp_settings`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `why_choose_us`
--
ALTER TABLE `why_choose_us`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `about_us`
--
ALTER TABLE `about_us`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `admins`
--
ALTER TABLE `admins`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `banners`
--
ALTER TABLE `banners`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `categories`
--
ALTER TABLE `categories`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- AUTO_INCREMENT for table `contact_information`
--
ALTER TABLE `contact_information`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `delivery_areas`
--
ALTER TABLE `delivery_areas`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `enquiries`
--
ALTER TABLE `enquiries`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `flavours`
--
ALTER TABLE `flavours`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `footer_settings`
--
ALTER TABLE `footer_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `marquee_products`
--
ALTER TABLE `marquee_products`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `orders`
--
ALTER TABLE `orders`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=51;

--
-- AUTO_INCREMENT for table `order_items`
--
ALTER TABLE `order_items`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=55;

--
-- AUTO_INCREMENT for table `products`
--
ALTER TABLE `products`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=15;

--
-- AUTO_INCREMENT for table `product_flavours`
--
ALTER TABLE `product_flavours`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=23;

--
-- AUTO_INCREMENT for table `product_images`
--
ALTER TABLE `product_images`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=32;

--
-- AUTO_INCREMENT for table `seo_settings`
--
ALTER TABLE `seo_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `settings`
--
ALTER TABLE `settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `whatsapp_settings`
--
ALTER TABLE `whatsapp_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `why_choose_us`
--
ALTER TABLE `why_choose_us`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `marquee_products`
--
ALTER TABLE `marquee_products`
  ADD CONSTRAINT `marquee_products_ibfk_1` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `order_items`
--
ALTER TABLE `order_items`
  ADD CONSTRAINT `order_items_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `order_items_ibfk_2` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `order_items_ibfk_3` FOREIGN KEY (`flavour_id`) REFERENCES `flavours` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `products`
--
ALTER TABLE `products`
  ADD CONSTRAINT `products_ibfk_1` FOREIGN KEY (`category_id`) REFERENCES `categories` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `product_flavours`
--
ALTER TABLE `product_flavours`
  ADD CONSTRAINT `product_flavours_ibfk_1` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `product_images`
--
ALTER TABLE `product_images`
  ADD CONSTRAINT `product_images_ibfk_1` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
