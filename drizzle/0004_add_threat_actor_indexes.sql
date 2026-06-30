CREATE INDEX `ta_last_active_idx` ON `threat_actors` (`lastActive`);--> statement-breakpoint
CREATE INDEX `ta_threat_level_idx` ON `threat_actors` (`threatLevel`);--> statement-breakpoint
CREATE INDEX `ta_name_idx` ON `threat_actors` (`name`);--> statement-breakpoint
CREATE INDEX `ta_updated_at_idx` ON `threat_actors` (`updatedAt`);--> statement-breakpoint
CREATE INDEX `ta_actor_type_idx` ON `threat_actors` (`actorType`);
