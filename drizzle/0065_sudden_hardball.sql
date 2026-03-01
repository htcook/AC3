CREATE TABLE `chat_messages` (
	`id` int AUTO_INCREMENT NOT NULL,
	`chat_msg_session_id` int NOT NULL,
	`chat_msg_role` enum('user','assistant','system','tool') NOT NULL,
	`chat_msg_content` text NOT NULL,
	`chat_msg_tool_name` varchar(128),
	`chat_msg_tool_result` json,
	`chat_msg_created_at` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `chat_messages_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `chat_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`chat_session_user_id` int NOT NULL,
	`chat_session_title` varchar(255) DEFAULT 'New Chat',
	`chat_session_role` varchar(64) NOT NULL DEFAULT 'operator',
	`chat_session_message_count` int DEFAULT 0,
	`chat_session_last_message_at` timestamp DEFAULT (now()),
	`chat_session_archived` boolean DEFAULT false,
	`chat_session_created_at` timestamp NOT NULL DEFAULT (now()),
	`chat_session_updated_at` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `chat_sessions_id` PRIMARY KEY(`id`)
);
