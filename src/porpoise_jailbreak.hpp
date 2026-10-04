/* Porpoise - asking the HEN to free Porpoise from the app sandbox.
 * Copyright (C) 2026 Ruben (Project Porpoise)
 * SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

namespace porpoise::jailbreak
{
/* Whether /data is there and Porpoise can write in /data/porpoise. */
bool data_reachable();
/* When it isn't: asks etaHEN / OnionHEN / Lapy JB Daemon to free this
 * process (a few seconds at most). Retries the file-based request up to
 * three times to handle the Lapy daemon's getHijacker timing race, and
 * verifies the actual credential bump after each round. Falls back to the
 * legacy port-based servers. True when /data is reachable afterwards. */
bool ensure();
} // namespace porpoise::jailbreak
