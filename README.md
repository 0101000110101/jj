You're right — I wrapped it in an outer ` ```markdown ` fence and then put ` ```lua ` fences inside it, which closes the outer fence at the first inner one. That's my mistake.

Here's the fix: **no outer fence at all.** Just raw markdown. Copy from the first line below (`# juju`) to the last line (`issues or PRs.`) and save as `README.md`.

---

# juju (Da Hood) — Full Source Analysis & Anticheat Reference

A complete static analysis of the "juju" Da Hood script. Written for game developers and anticheat engineers who need to understand exactly what the script does, what remotes it exploits, and how to detect it server-side.

> **Scope:** This document is a defensive security analysis. It contains excerpts of the analysed script for detection purposes only. It is not a working exploit and no runnable payload is included.

---

## Table of Contents

- [Overview](#overview)
- [Threat Model](#threat-model)
- [File Layout at Runtime](#file-layout-at-runtime)
- [Executor Support](#executor-support)
- [Load-Time Behaviour](#load-time-behaviour)
- [Anticheat Neutralisation](#anticheat-neutralisation)
- [Remote Event Interception](#remote-event-interception)
- [Character Hooks](#character-hooks)
- [Feature Catalogue](#feature-catalogue)
- [Network Footprint](#network-footprint)
- [Detection Cheat Sheet](#detection-cheat-sheet)
- [Server-Side Mitigation Checklist](#server-side-mitigation-checklist)
- [Hardcoded Constants](#hardcoded-constants)
- [Glossary](#glossary)

---

## Overview

| Property | Value |
|---|---|
| Target game | Da Hood (PlaceId varies) |
| Language | Luau |
| Size | ~4,700 lines |
| Obfuscation | None. Uses Luraph-style `LPH_*` macros stubbed to identity functions |
| UI renderer | Custom Drawing proxy (executor `Drawing.new`, not Instances) |
| Executor support | AWP, Nihon, Wave, Swift, Potassium, generic |
| Network calls | 4 endpoints total (see Network Footprint) |
| Token grabber | None detected |
| Persistence | Files under `juju recode/` in executor workspace |

The script is delivered as plain Luau. The `LPH_JIT_MAX`, `LPH_NO_VIRTUALIZE`, `LPH_ENCSTR` identifiers are Luraph obfuscator signatures, but they are declared at the top of the file as pass-through functions:

    if not LPH_OBFUSCATED then
        LPH_JIT_MAX = function(...) return ... end
        LPH_NO_VIRTUALIZE = function(...) return ... end
        LPH_ENCSTR = function(...) return ... end
        LPH_NO_UPVALUES = function(...) return ... end
        LPH_JIT = function(...) return ... end
    end

Every occurrence of `LPH_JIT_MAX(fn)()` is therefore a direct call to `fn`. There is no runtime cost, and no code is hidden.

---

## Threat Model

| Capability | Impact | Server-visible? |
|---|---|---|
| Forged `ShootGun` origin/aim | Perfect accuracy, wall penetration | Yes — origin vector is validated |
| Desync via velocity spoofing | Position desync, dodge server hits | Partially — snapshot cadence visible |
| Remote filtering (AC heartbeat suppression) | Server stops receiving check-ins | Yes — heartbeat gap is measurable |
| Kick shield | Client ignores server `Player:Kick()` | Yes — client rejoins after kick |
| Rate exploitation | Multiple actions per tick | Yes — remote call counting |
| Client-side tool manipulation | Fake skins, materials, animations | Sometimes — attribute/texture differences |
| Visual cheating (ESP, chams) | Information advantage | No |
| Aimbot (assisted) | Combat advantage | Yes — input kinematics |

---

## File Layout at Runtime

The script writes to the executor workspace on first load:

    juju recode/
    ├── assets/
    │   ├── api.lua              # Drawing fallback library (downloaded)
    │   ├── sparkle.ogg
    │   ├── skeet.ogg
    │   ├── neverlose.ogg
    │   ├── break.ogg
    │   ├── mc bow.ogg
    │   ├── primordial.ogg
    │   ├── rust.ogg
    │   ├── sexy.ogg
    │   ├── jaydes.png
    │   ├── 1.png
    │   ├── 2.png
    │   ├── logo.png
    │   └── saturation.png
    ├── custom/
    │   ├── textures.json
    │   ├── character.rbxm
    │   ├── pinksky.rbxm
    │   ├── scar.ogg
    │   ├── x hit.rbxm
    │   ├── blossom aura.rbxm
    │   └── spam.json
    ├── themes/
    │   └── default.th
    ├── addons/                   # User-supplied .luau files
    ├── configs/                  # XOR+base64 encrypted .cfg files
    └── data.dat                  # JSON, notification/theme/favorites/autoload prefs

---

## Executor Support

Branch points throughout the code:

    if identifyexecutor() == "AWP" or identifyexecutor() == "Nihon" then
        cleardrawcache()
    end

    local create_drawing = identifyexecutor() == "Wave"
        and create_fake_drawing
        or create_real_drawing

    local create_drawing = (identifyexecutor() == "Swift"
        or identifyexecutor() == "Potassium")
        and create_fake_drawing
        or create_real_drawing

The `fake_drawing` vs `real_drawing` distinction is significant: some executors have a broken or missing native `Drawing` and the script falls back to a pure-Instance UI implementation. In both cases, the code path is determined by `identifyexecutor()` at load time.

---

## Load-Time Behaviour

Before the menu is built, the script performs these privileged operations:

1. Calls `getgenv()["juju"] = {}` to reserve the addon namespace.
2. Registers the anticheat neutralisation block (see below).
3. Downloads `api.lua` from GitHub and `loadstring`s it.
4. Writes every file in the asset tree to disk if not present.
5. Registers the `PhysicsRepRootPart` metatable hook on the local `HumanoidRootPart`.
6. Installs the `MainEvent.__namecall` hook on the replicated storage remote.

Order matters: the neutralisation block runs **before** any game script can register its own anticheat listeners.

---

## Anticheat Neutralisation

### Registry Wipe

Iterates the Lua registry, finds any closure whose `getinfo().source` contains exactly one dot (i.e., a script in the game tree, not a ReplicatedStorage module) and replaces it with an empty function.

    for i, v in reg do
        if typeof(v) == "function" and islclosure(v) then
            local info = getinfo(v)
            if count_dots(info.source) == 1
                and not info.source:find("Replicated") then
                neutralize[i] = true
            end
        end
    end
    for i in neutralize do reg[i] = function() end end

**Effect:** Any local anticheat script that stores its callback in the registry is silently disabled. This targets detection scripts that use `spawn(function() while true do ... end end)` loops stored as registry entries.

### Signal Connect Blocker

    old = safe_hook_function(signal.__index, function(self, index)
        if (index:find("^[Cc]onnect")) and getinfo(3) then
            local source = getinfo(3).source
            if count_dots(source) == 1
                and not source:find("Replicated") then
                return function()
                    return setrawmetatable(newproxy(true), connection)
                end
            end
        end
        return old(self, index)
    end)

**Effect:** Any `.Connect(...)` call from a one-dot script (i.e., game-side script, not a module) receives a fake connection object. The callback **is never registered**. This is the single most dangerous neutralisation for anticheat systems: an anticheat that subscribes to `Player.CharacterAdded` on the client from a `LocalScript` will silently receive zero events.

### GetFocusedTextBox Override

    old2 = safe_hook_function(
        cloneref(game:GetService("UserInputService")).GetFocusedTextBox,
        newcclosure(function() return nil end)
    )

**Effect:** Breaks any UI-based anticheat that inspects textbox focus as a client state signal.

### Constant Sweep

A 10-second loop walks `getgc(true)` and forces any table field whose key name matches a suspicious list to `false`:

    teleportdetect, checker_1, checker, gui_check, onemoretime, checkingspeed,
    banremote, permaidban, kickremote, br_kickpc, br_kickmobile, detected,
    shouldkick, flagged, anticheat, banned, punish, restrict, exploit, cheat,
    flying, orbit, noclip, autofarm, standbot, autokill, aimmanipulation,
    teleport, speed, report, monitor, scanner, submitreport, sentinel,
    watchdog, detection, violation, screenshot, snitch, staff, desync,
    gliding, fly, bhop, strafe, wallbang, silentaim, aimbot, triggerbot,
    reach, backtrack, spinbot, jitter, anti_aim, anti aim, resolver,
    blatant, suspicious, heuristic, velocity_check, walkspeed, jump_power

**Effect:** Any anticheat state machine that flips a boolean field with a name in that list (e.g. `local state = { flagged = false }`) gets reset every 10 seconds. The list is a direct fingerprint of what the script author fears being detected by.

### Kick Shield

    hookmetamethod(game, "__namecall", newcclosure(function(self, ...)
        if getnamecallmethod() == "Kick"
            and self == local_player
            and not checkcaller() then
            local reason = tostring(...)
            if not allowed_kick_reasons[reason] then
                warn("[juju] blocked ac kick: " .. reason)
                return
            end
        end
        return old_namecall_shield(self, ...)
    end))

Only `"R.."` and `"H.."` (the script's own rejoin/hop reasons) are allowed. Every other `Player:Kick()` call is dropped client-side.

**Detection:** Server-side, a ban/kick that fires and the player *rejoins the same server* within 30s without a `PlayerRemoving` event is proof the kick was blocked.

---

## Remote Event Interception

The script hooks `ReplicatedStorage.MainEvent`:

    setrawmetatable(event, {
        __namecall = function(self, ...)
            if getnamecallmethod() == "FireServer" then
                local packet = args[1]
                if packet == "ShootGun" then
                    -- substitute forged origin/pos/hitbox
                elseif packet == "UpdateCursorImage" then
                    inventory["Parent"]["CursorImage"]["Value"] = args[2]
                    return
                elseif packet == "CHECKER_4" then return end
                elseif packet == "CHECKER_1" then return end
            end

            if getnamecallmethod() == "FireServer"
                or getnamecallmethod() == "InvokeServer" then
                local name = self.Name:lower()
                if name:find("log")
                    or name:find("report")
                    or name:find("monitor")
                    or name:find("anticheat")
                    or name:find("ac_")
                    or name:find("_ac")
                    or name:find("cheat")
                    or name:find("sentinel")
                    or name:find("watchdog")
                    or name:find("detect")
                    or name:find("ban")
                    or name:find("snitch")
                    or name:find("staff")
                    or name:find("violation")
                    or name:find("punish")
                    or name:find("flagged")
                    or name:find("enforce")
                    or name:find("moderate") then
                    return
                end
            end

            return old_namecall(self, ...)
        end
    })

**Critical implication for anticheat design:** Any RemoteEvent or RemoteFunction whose *instance name* contains one of those substrings is silently suppressed. If your anticheat uses a remote named `AntiCheatPing`, `SentinelCheck`, `ReportPosition`, or similar, it will never fire from a compromised client.

**Recommendation:** Name your AC remotes with opaque identifiers that cannot be pattern-matched (e.g. random 6-character strings generated at server start and passed to trusted clients through a non-string channel).

---

## Character Hooks

### HumanoidRootPart CFrame Spoof

    local old_index = getrawmetatable(hrp).__index

    local new = {
        ["__index"] = newcclosure(function(self, index)
            if not checkcaller()
                and self
                and index == "CFrame"
                and (#anti_aim ~= 0 or purchasing)
                and not vehicle then
                return local_client_position
            end
            return old_index(self, index)
        end)
    }
    setrawmetatable(hrp, new)

**Effect:** When any non-script caller (game script) reads `HumanoidRootPart.CFrame` during a desync frame, they receive the *previous* frame's CFrame. The client physically teleports; the server snapshot reflects a stale position.

### Humanoid WalkSpeed / JumpPower Hook

    ["__newindex"] = newcclosure(function(self, index, value)
        if not checkcaller() and self then
            if index == "WalkSpeed"
                and flags["remove_slowdowns"]
                and value < 16 then
                s[index] = value
                if flags["remove_slowdowns"] then return end
            elseif index == "JumpPower" then
                if flags["remove_jump_cooldown"] and value == 0 then
                    s[index] = 0
                    return
                else
                    value = flags["jump_power"]
                        and flags["jump_power_value"]
                        or value
                end
            end
        end
        return old_newindex(self, index, value)
    end

**Effect:** Slowdowns (stuns, ragdolls) that write `WalkSpeed < 16` are eaten. `JumpPower` writes are replaced with the user's configured value.

### Vehicle CFrame Spoof

Identical pattern applied to the vehicle model when the local player is seated. Extends the desync window to driving.

---

## Feature Catalogue

### Ragebot

The main combat feature. Located under tab `main > ragebot`.

#### Fire Packet

    local _spread = math_random(1, 4) * 0.001
    local pos = ragebot_aim_position + vector3_new(
        math_random(960, 1080) * 0.001,
        (math_random(-25, 25) * 0.001) + _spread,
        (math_random(-25, 25) * 0.001) - _spread
    )

    local _jitter = math_random(0, 1) == 0 and 1 or -1
    local origin = local_server_position + vector3_new(
        0.004 + (math_random(-10, 10) * 0.001),
        3.0208 + (math_random(-18, 18) * 0.001) + _jitter * math_random(1, 3) * 0.001,
        -0.048 + (math_random(-10, 10) * 0.001)
    )

    event:FireServer("ShootGun", handle, origin, pos, hitbox, dir)

**Detection:**
- `origin.Y - character.Position.Y` should be exactly `3.0208` for a legit shot. Any shot whose origin deviates more than ~0.3 studs is forged.
- `origin.X` should be within `[-0.01, 0.01]` of character position. `origin.Z` should be within `[-0.06, 0.06]`.
- The *variance* of origin across shots is anomalously low (microsecond-scale jitter) compared to human input variance.

#### Auto-Fire Gate

    old_time - last_fire > fire_cooldown
        + (math_random(-20, 20) * 0.001)
        + (math_random(0, 1) == 0 and math_random(5, 15) * 0.001 or 0)

The jitter is bounded by 35 ms. A server-side sliding-window fire-rate check with a window of ~2 seconds and a threshold near the weapon's nominal fire rate will catch this; humans have bimodal inter-shot distributions that this doesn't reproduce.

#### Resolver (Cluster Resolve)

The most sophisticated subsystem. Maintains a sliding 2.75 s window of torso position samples, hashes them into a spatial grid, finds the densest cluster, mean-shifts to the core, and returns the centroid as the "true" position. Used when the target is desynced.

Constants:

| Constant | Value | Meaning |
|---|---|---|
| `cluster_window_time` | 2.75 s | Sliding window length |
| `cluster_forgiveness` | 14.4 studs | Cluster radius |
| `cluster_void_bonus` | 5 studs | Bonus radius when sample near origin |
| `cluster_distance_penalty` | 2 | Radius penalty per 100 studs of distance |
| `cluster_min_size` | 4 | Minimum samples to form a cluster |

#### Damage Position Search

`find_damage_position` mirrors the exact `ShootGun` payload server-side and raycasts to verify the shot hits the target's hitbox. Two phases:

1. **Phase 1** — one exact-packet raycast per candidate. Ranked by hit tier (Head > Root > body).
2. **Phase 2** — up to 24 ring samples around survivors at offsets `±2.4`, `±1.7`, and combinations.

The origin used is identical to the fire origin (`Vector3(0.004, 3.0208, -0.048)`).

#### Hit Confirmation

    get_bullet_result = LPH_JIT_MAX(function(player, part, old_server_position, aim_position, target_velocity, did_defensive)
        local old_health = data[9]
        repeat wait() until clock() - start > 0.25 + local_ping/1000 or shot_count > old_count
        if data and older_health ~= data[9] or older_data ~= data then
            local new_health = data[9]
            if new_health < old_health then
                return signals["on_local_bullet_confirmed"]:Fire(player, part, ...)
            else
                return signals["on_local_bullet_failed"]:Fire(player, part, ...)
            end
        end
    end)

Reads the target's health 0.25 s + ping after each shot. Feeds the visual feedback loop and the resolver's trust score.

#### Backtrack

Clones every target player, hides them at `(0, 9e9, 9e9)`, and replays their CFrame history lagged by `backtrack_length` seconds. The clone's parts have the same names as the real character's, so server-side hit detection still validates.

#### Follow Target

Three styles: `random`, `random spam`, `strafe`.

- `random` — teleports to a random offset from the target at 12 Hz.
- `random spam` — alternates between a stable offset and a full-range random void position.
- `strafe` — orbits the target at `follow_target_distance` studs.

#### Rapid Fire

Finds the tool's `Activated` connection and replaces any numeric constant or upvalue in `(0, 10)` with `-10000`:

    for _, constant in getconstants(old) do
        if type(constant) == "number"
            and constant ~= -10000
            and constant ~= 0.05 then
            constant_cache[old] = constant
            setconstant(old, _, -10000)
            break
        end
    end

Effect: the client-side cooldown timer goes negative. Fire rate becomes input-limited.

#### Other Settings

- `prediction` slider — `0` = auto (`ping/500`), `2000` = disabled
- `fire_cooldown` slider — 0–300 ms
- `shot_delay` — 0–1000 ms added before each shot
- `ragebot_field_of_view` — angular FOV
- `ragebot_hitbox` — `head` or `root`
- `target_selection` — 5 modes: closest-to-mouse, closest-to-character, lowest-health, highest-wanted, random
- `target_statuses` — friendly/neutral/enemy filter
- `ignore_if` — invulnerable / in void / knocked
- `untarget_when` — dead / knocked / flung / better target / invulnerable

---

### Legitbot

Tab `main > legitbot`.

#### Mouse Metatable Hook

    ["__index"] = newcclosure(function(self, index)
        local force = getthreadidentity() == 5
        if (force or not checkcaller()) and self and index == "Hit" then
            if silent_aim_position or ragebot_aim_position then
                if force or getcallingscript()["Name"]:find("Gun") then
                    if ragebot_aim_position then
                        return cframe_new(ragebot_aim_position)
                    end
                    if math_random(1,100) > silent_aim_redirect_chance then
                        return cframe_new(silent_aim_position)
                    end
                end
            end
        end
        return old_index(self, index)
    end)

**Effect:** Any call to `mouse.Hit` from a script whose name contains `"Gun"` returns the ragebot aim position or silent aim position. This is the silent-aim mechanism.

#### Aim Assist

Smooths the mouse (`mousemoverel`) or camera CFrame toward the target. Six smoothing modes: `exponential`, `constant`, `random`, `quart`, `quad`, `back`, `sine`. Supports a dead zone (inner radius where no aim is applied) and multipoint (samples a point inside the hitbox between the cursor and the hitbox surface).

#### Silent Aim

Feeds a fake `mouse.Hit` without moving the user's view. Supports multipoint and a "max curve" mode that bends the aim from the cursor towards the target over a viewport-space arc.

#### Triggerbot

Raycasts from the mouse each frame; when the ray hits a target part, sends `mouse1press` / `mouse1release`. Configurable hitboxes (head/torso/arms/legs), cooldown, hover time, and delay.

#### Reduce Shotgun Spread

Replaces the `math` table of the shotgun's fire function with a closure where `random()` returns `math_random() * reduce_amount`.

#### Backtrack

Same mechanism as the ragebot backtrack — clone characters, replay lagged CFrame.

---

### Anti-Aim / Desync

Tab `main > ragebot > anti`.

#### Void Hide

Five types:

| Type | CFrame applied for one render step |
|---|---|
| `vc server` | `(0, random(-2^31, 2^31), 0)` |
| `random` | `(random(-2^31, 2^31), random(-400, 2^31), random(-2^31, 2^31))` |
| `bait` | Stable position within `bait_distance` of the player |
| `deep y` | `(rand(-15,15), -999999999, rand(-15,15))` |
| `random bait` | Alternates: origin (0,0,0), corner (±1,±1,±1), random |

Every method ends with restoring the original CFrame on the next frame. The server snapshot taken during the void frame is what the server thinks your position is.

Force/disable conditions include: not full health, tabbed out, reloading, target selected, following target, target knocked, purchasing, auto stomping, knocked.

#### Velocity Desync

    local velocity = velocity_desync_type == "high y" and vector3_new(0, 16384, 0)
        or velocity_desync_type == "limit" and vector3_new(
            math_random(-9223372036854775808, 9223372036854775807), ...)
        or velocity_desync_type == "low" and vector3_new(
            math_random(1,2) == 1 and -300 or 300, ...)
        or velocity_desync_type == "high" and vector3_new(
            math_random(1,2) == 1 and -16384 or 16384, ...)
        or vector3_zero

    hrp["AssemblyLinearVelocity"] = velocity
    if velocity_desync_rotate then
        hrp["AssemblyAngularVelocity"] = velocity
    end
    render_stepped_wait(render_stepped)
    hrp["AssemblyLinearVelocity"] = old_linear_velocity

**Effect:** One frame of absurd velocity corrupts the server's predicted position. This is the desync primitive that makes the resolver necessary.

#### Sender Rate Value

    setfflag("S2PhysicsSenderRate", tostring(value))

In "custom" mode, sets the physics replication rate to a user value (0–500 Hz). In "automatic", matches the current FPS. This controls how often the client sends physics snapshots to the server.

---

### Movement

Tab `misc > main > movement`.

| Feature | Flag | Mechanism |
|---|---|---|
| Remove jump cooldown | `remove_jump_cooldown` | Eats `JumpPower = 0` writes |
| Remove slowdowns | `remove_slowdowns` | Eats `WalkSpeed < 16` writes |
| Jump power | `jump_power` + `jump_power_value` | Overrides `JumpPower` writes |
| Anti-trip | `anti_trip` | Disables `FallingDown` HumanoidState |
| Anti-sit | `anti_sit` | Disables `Seated` HumanoidState |
| Noclip | `noclip` | Sets `CanCollide = false` on every part each frame |
| Speed | `speed` | Adds `MoveDirection * dt * value * 16` to HRP CFrame |
| Flight | `flight` | Constant upward velocity + WASD horizontal |
| Animation breaker | `animation_breaker` | Freezes/jitters `AnimationTrack.TimePosition` |
| Animation player | `animation_player` | Loads and plays arbitrary animations |
| Trash talk | `trash_talk` | Fires chat remote on schedule |
| Spinbot | `spinbot` | Rotates HRP around Y each frame |

**Speed styles:**

| Style | Behavior |
|---|---|
| `normal` | Direct `MoveDirection * dt * value` |
| `bhop` | `normal` + `ChangeState(Jumping)` while any movement key held |
| `minecraft` | `bhop` + velocity Y boost on jump |
| `slippery` | Lerps a velocity vector, applies as `HRP.Velocity` |

---

### Combat Utility

Tab `main > ragebot > utility`.

| Feature | Description |
|---|---|
| Safe purchasing | Skips purchases when enemies/targets are near |
| Auto loadout | Buys and equips a configured loadout + ammo |
| Follow target | Desync-follows the current ragebot target |
| Auto stomp | Fires `Stomp` remote every 25 ms on knocked targets |
| Auto knife | Buys, equips and swings a knife |
| Auto bag | Buys and applies a BrownBag to knocked targets |
| Auto ammo | Buys ammo when clip count is low |
| Auto armor | Buys `high-medium armor` when armor < threshold |
| Auto heal | Buys and activates `[Popcorn]` when HP low |
| Auto mask | Buys and equips a ninja mask |
| Anti stomp | Teleports out of the map on `K.O.` |
| Anti taser | Teleports randomly for 0.6 s when a taser beam attaches |
| Rapid fire | Neutralises fire cooldowns via `setconstant` |

#### Auto Stomp

    if tick - auto_stomp_tick > 0.025 then
        auto_stomp_tick = tick
        event:FireServer("Stomp")
    end

40 `Stomp` calls per second.

#### Auto Bag

    hrp["Velocity"] = vector3_zero
    hrp["CFrame"] = cframe_new(torso["Position"] + vector3_new(0, 2.3, 0))

    pcall(bag.Activate, bag)
    event:FireServer("BagCharacter", target[3])

Fires `BagCharacter` directly at a target character reference without requiring a prior hit.

---

### Visuals / ESP

Tab `visuals > players`.

Rendered with the executor's `Drawing` library (no Instances except for `Highlight` and `BoxHandleAdornment` chams).

| Component | Drawing type | Purpose |
|---|---|---|
| Box + outline | Square | 2D bounding box |
| Name | Text | Player or display name |
| Health bar | Square + optional Image | Health bar with gradient |
| Health text | Text | Numeric HP |
| Armor bar | Square + optional Image | Armor bar |
| Tool text | Text | Current tool name |
| Tool icon | Image | Weapon icon from `tool_icon_data` |
| Chams | `BoxHandleAdornment` | Part-box outlines (CoreGui) |
| Highlight | `Highlight` instance | Depth-tested outline |
| Image | Image | Body silhouette overlay |
| Material | Body material | Neon / forcefield body |

Per status (friendly / neutral / enemy) color pickers exist for every visual element.

**Name hider** sets:

    humanoid["DisplayName"] = ""   -- zero-width space
    humanoid["HealthDisplayType"] = Enum["HumanoidHealthDisplayType"]["AlwaysOff"]

**Detections:**
- `Highlight` instances in `CoreGui` that don't correspond to a server-side decoration
- `BoxHandleAdornment` instances in `CoreGui`
- Character clones in `workspace.Players` (backtrack models, distinguishable by the `"1"` attribute)
- Humanoid `DisplayName` set to invisible Unicode
- `HealthDisplayType` forced to `AlwaysOff`

---

### World Visuals

Tab `visuals > general > world`.

| Feature | Instance created | Server-visible |
|---|---|---|
| Background noise | `Sound` in HUI | No |
| Lighting mode | `Lighting.Technology` write (metatable spoofed) | No |
| World time | `Lighting.ClockTime` write (metatable spoofed) | No |
| Atmosphere | `Atmosphere` in Lighting | No |
| Saturation | `ColorCorrectionEffect.Saturation` | No |
| Contrast | `ColorCorrectionEffect.Contrast` | No |
| Textures | `MaterialVariant` in MaterialService | Yes |
| Ambient | `Lighting.Ambient/OutdoorAmbient` | No |
| Weather | `Part` + `ParticleEmitter` in `workspace.Ignored` | No |
| Skybox | Sky property writes | No |
| Tint | `ColorCorrectionEffect.TintColor` | No |

**MaterialVariant detection:** The server never creates `MaterialVariant` instances. If a `MaterialService` child with a name matching a texture pack key (`Grass`, `Slate`, `Sand`, `Wood`, `Brick`, `Concrete`, `CorrodedMetal`, `Metal`, `WoodPlanks`) is observed during a client session, it was created by the script.

**Lighting metatable spoof:**

    ["__newindex"] = function(self, property, value)
        if self and not checkcaller() and spoofing[property] then
            original[property] = value
            return  -- write goes to local cache, not Lighting
        end
        return old_new_index(self, property, value)
    end

    ["__index"] = function(self, property)
        if self and not checkcaller() then
            return spoofing[property] and original[property]
                or old_index(self, property)
        end
        return old_index(self, property)
    end

Game scripts read the original values. Only the renderer sees the new ones.

---

### Skin Changer

Tab `visuals > skins`.

Reads `ReplicatedStorage.SkinModules` and enumerates skins per gun. When a gun is equipped:

    local handle = wait_for_child(gun, "Handle", 1)
    handle:SetAttribute("SkinName", skin)

    local skin_data = list[skin] or defaults[gun_name]
    local default = gun["Default"]
    local fake = find_first_child_of_class(default, "MeshPart")
    if fake then destroy(fake) end

    if mesh then
        local new_fake = clone(new_mesh)
        new_fake["CFrame"] = default["CFrame"]
        local weld = create_instance("Weld", {
            ["Part0"] = default, ["Part1"] = new_fake,
            ["C0"] = skin_data["CFrame"] or cframe_new(),
            ["Name"] = "\0", ["Parent"] = default
        })
        new_fake["Name"] = "\0"
        new_fake["Parent"] = default
        default["Transparency"] = 1
    else
        default["Transparency"] = 0
        default["TextureID"] = skin_data["TextureID"] or ""
    end

**Detections:**
- Any tool with a `SkinName` attribute that the server never set
- Any `Default` part with `Transparency = 1` while the handle is visible
- A `Weld` named `"\0"` on `Default`
- Any child of `Handle` whose `Name` is empty

The script also calls `setfflag("ReplicatorAnimationTrackLimitPerAnimator", "-1")` before playing knife animations, then restores `50`.

**Custom skins** are loaded from `juju recode/custom/*.skin` (JSON), with fields `mesh`, `beam`, `shoot_sound`, `handle_particle`, `muzzle_particle`, `animation`, `animation_speed`, `texture`, `tool`, `name`.

---

### Miscellaneous

| Feature | Tab | Description |
|---|---|---|
| Remove flintlock knockback | misc > utility | `setupvalue` on the flintlock's `Activated` connection |
| Unlock custom crosshair | misc > utility | Sets `CursorImage.Value` and calls `UpdateCursorIcon` |
| Unlock animation packs | misc > utility | Rewrites `AnimationPack` and `AnimationPlusPack` |
| Unlock camera distance | misc > utility | `CameraMaxZoomDistance = 9e9` |
| Remove anti-gun macro | misc > utility | Replaces `HoldGunBool` constant with `_!_` in `BaseCamera` |
| Remove flashbang | misc > utility | Drops `FLASHBANG` packet |
| Automatic guns | misc > utility | Fires `Activated` connection while M1 held |
| Remove recoil | misc > utility | Drops `ShootingRecoil` packet |
| Auto vehicle | misc > utility | Fires vehicle spawner prompts |
| Semi god | misc > utility | Random void velocity while on foot |
| Auto reload | misc > utility | Fires `Reload` on low ammo or target death |
| Detect staff | misc > utility | Watches group roles, optionally kicks self |
| Redeem codes | misc > utility | Fires `EnterPromoCode` for `SHARK`, `DOG` |
| Get vehicle | misc > utility | Teleports to empty vehicle and fires `Ride` prompt |
| Force reset | misc > utility | Sets Humanoid `Health = 0` |
| Server tools | misc > utility | Join script / rejoin / hop |
| Auto save friendlies | misc > players | Teleport-grabs knocked friendlies |
| Auto set statuses | misc > players | Classifies by friendship / crew |
| Player editor | misc > players | Manual status, teleport, set target |
| Character highlight | visuals > players | `Highlight` on local character |
| Custom character | visuals > players | Applies a `HumanoidDescription` from user ID or `.rbxm` |
| Animated tools | visuals > players | Rotates `Tool.Grip` each frame |
| Material tools | visuals > players | Neon/forcefield gun material |
| Particle aura | visuals > players | Spawns aura particles into body parts |
| Show arms in first person | visuals > players | Sets `LocalTransparencyModifier = 0` on arm parts |

---

## Network Footprint

Every outbound call in the script:

| Endpoint | Method | Purpose | Sends |
|---|---|---|---|
| `github.com/d1rtylegitness/juju/raw/.../api.lua` | GET | `loadstring`'d as the Drawing fallback | — |
| `github.com/d1rtylegitness/juju/raw/.../*.png` | GET | UI textures | — |
| `github.com/d1rtylegitness/juju/raw/.../*.ogg` | GET | Sound effects | — |
| `github.com/d1rtylegitness/juju/raw/.../*.json`, `*.rbxm` | GET | Custom assets | — |
| `games.roblox.com/v1/games/<PlaceId>/servers/Public` | GET | Server-hop list | — |
| `discord-lookup-api-pied.vercel.app/v1/user/<id>` | GET | Config author display | Discord ID (if linked) |

**No token grabber. No `.ROBLOSECURITY` access. No webhook exfiltration.**

**One trust dependency:** `api.lua` is downloaded and executed. If the author's GitHub account is compromised, arbitrary code executes with full executor privileges. This is a supply-chain risk, not a proven backdoor.

---

## Detection Cheat Sheet

Server-side signals, ordered by signal-to-noise ratio.

### Highest confidence

1. **`ShootGun` origin validation**

       expected = character.HumanoidRootPart.Position + Vector3(0.004, 3.0208, -0.048)
       if (received_origin - expected).Magnitude > 0.3 then flag end

   Every shot from this script fails this by more than 0.3 studs on some shots, and every shot's Y is within 0.02 studs of `3.0208`.

2. **`Stomp` rate limit** — 40 calls per second is impossible for a human.

3. **`BagCharacter` without prior hit** — the legit flow requires a bag hit first; direct calls bypass this.

4. **Melee tools firing `ShootGun`** — knife and similar melee tools have no range, so `ShootGun` from them is always forged.

5. **`PhysicsRepRootPart` set for >1 frame** — this hidden property is a replication anchor the exploit uses for the `connection` feature.

6. **Origin variance over shots** — the jitter is uniform microsecond-scale noise. Humans produce log-normal distributions.

7. **`Reload` rate limit** — auto reload fires repeatedly; a human can't send 30 reloads in a minute.

### Medium confidence

8. **`Grabbing` rate limit** — auto save fires `Grabbing` every 30 ms.

9. **`EnterPromoCode` rate limit** — the redeem-codes feature fires 2 codes with a 6 s gap.

10. **`SkinName` attribute set on a tool** — the server never sets this. Any tool with `SkinName` was tampered with.

11. **`DisplayName` on a Humanoid set to invisible Unicode** — the nametag hider.

12. **`HealthDisplayType = AlwaysOff`** — same feature.

13. **Character clone in `workspace.Players`** with attribute `"1"` — backtrack model.

14. **`MaterialVariant` in `MaterialService`** with a known pack name.

15. **`Highlight` in `CoreGui`** whose Adornee is a character — chams / player highlight.

16. **`BoxHandleAdornment` in `CoreGui`** — chams.

17. **Remote name filtering** — count the client's `FireServer` calls against the number of code paths that should trigger them. A `CHECKER_1` or `CHECKER_4` remote that never fires is a strong signal.

18. **Client rejoin after `Player:Kick`** — if a player rejoins within 30 s after being kicked and no `PlayerRemoving` was observed, the kick was client-blocked.

### Lower confidence (correlates with cheating but has false positives)

19. **Position snapshots at `(0, 0, 0)` or `|Y| > 5000`** — void hide.

20. **Position delta > 50 studs per tick** — speed / teleport.

21. **`AssemblyLinearVelocity` magnitudes in the thousands** — velocity desync.

22. **`S2PhysicsSenderRate` anomalies** — packet cadence over a 5 s window.

23. **Humanoid `WalkSpeed` reported below `16`** while the character is in a `Running` state — the slowdown remover, but also has legit gameplay sources.

---

## Server-Side Mitigation Checklist

Ordered by ease of implementation.

- [ ] **Validate every `ShootGun` origin.** Reject any shot where `|origin - (HRP.Position + Vector3(0.004, 3.0208, -0.048))| > 0.3`.
- [ ] **Rate-limit each RemoteEvent per player** with a sliding window. Nominal rates for Da Hood are in the Detection Cheat Sheet.
- [ ] **Require prior hit for `BagCharacter`.** Track the last time each player's projectile hit each target; reject `BagCharacter` if >2 s.
- [ ] **Reject `ShootGun` from non-ranged tools.**
- [ ] **Strip all `SkinName` attributes** on tool equip and re-apply server-side values.
- [ ] **Rate-limit `Player:Kick` follow-up.** If a player rejoins within 30 s of a kick without a clean disconnect, apply a longer ban.
- [ ] **Log all `EnterPromoCode`, `Reload`, `Grabbing` calls** with timestamps; build player histograms and flag outliers.
- [ ] **Clamp `CameraMaxZoomDistance`** server-side (camera properties are replicated).
- [ ] **Bound `Humanoid.WalkSpeed` / `JumpPower`** on the server. Ignore client writes.
- [ ] **Do not name any remote with a substring from the filter list** (`log`, `report`, `anticheat`, `sentinel`, `watchdog`, `detect`, `ban`, `staff`, ...). Use opaque identifiers generated at server start.
- [ ] **Do not put the AC heartbeat on a remote that shares a name with any other remote.** The script's filter matches on instance name; a unique name is still filterable, but at least AC detection of a missing heartbeat is trivial.
- [ ] **Log `PhysicsRepRootPart` writes.** This hidden property has no legitimate use; any write is an exploit signal.
- [ ] **Track `AssemblyLinearVelocity` extremes** per player.
- [ ] **Verify snapshot physics.** Physics replication should be server-authoritative. If `S2PhysicsSenderRate` is client-controlled in your build, disable that flag.

---

## Hardcoded Constants

Values the script depends on that are useful for detection tuning.

### Gun Origin Offsets

| Axis | Value | Range |
|---|---|---|
| X | `0.004` | ±0.01 |
| Y | `3.0208` | ±0.018 |
| Z | `-0.048` | ±0.01 |

### Aim Position X Offset

`960..1080` millistuds → `0.96..1.08` studs.

### Staff Group IDs

- `10604500`
- `17215700`

### Hardcoded Admin User IDs

- `163721789`
- `93101606`
- `439942262`
- `29242182`
- `1830168970`
- `2371804259`

### Config Encryption

- Key: `"^^^^^^^^^^^^^^^^^^^^"` (20 carets)
- Encoding: base64 + XOR + 4-digit salt (prepended, reversed-appended)

### Hardcoded Redeem Codes

- `SHARK`
- `DOG`

### Config File Path

`juju recode/configs/*.cfg`

---

## Glossary

| Term | Meaning |
|---|---|
| **Ragebot** | Aim-assist that fires at the target directly, often ignoring visibility |
| **Legitbot** | Aim-assist with smoothing intended to appear human |
| **Silent aim** | Aim redirection that doesn't change the user's view |
| **FOV** | Field of view; angular radius where the aimbot will engage |
| **Hitbox** | The specific body part the aimbot targets (head / root) |
| **Backtrack** | Replaying a target's past position as a hitbox |
| **Desync** | Making the client position differ from the server position |
| **Void / void hide** | Teleporting to extreme coordinates to force a stale server snapshot |
| **Resolver** | A technique to reconstruct a desynced target's real position |
| **Cluster resolver** | Density-based resolver using spatial hashing and mean-shift |
| **Chams** | Colored overlay on a player model, visible through walls |
| **Triggerbot** | Automatic fire when the crosshair is over a target |
| **ESP** | Extrasensory perception; any off-screen player visibility feature |
| **Tracer** | A line from the shooter to the target |
| **Hit marker** | Visual confirmation of a confirmed hit |
| **Prediction** | Leading a target's movement to account for projectile travel time |
| **Safe purchasing** | Deferring shop interactions until no combat pressure |
| **Anti-aim** | Techniques to make the local player harder to hit |
| **AA** | Shorthand for anti-aim |
| **HvH** | Hack vs. hack; matches between two cheaters |

---

## License

This document is provided for educational and defensive security purposes. Do not use it to develop or distribute cheats.

## Contributing

Detection suggestions, corrections, or additional signals are welcome as issues or PRs.

---

That's the whole thing — no outer fence, no nested fences, no copy breakage. Select from `# juju` down to `issues or PRs.` and save.

One thing to note: I switched the inner code blocks from ```` ```lua ```` fences to **4-space indented blocks**. That's a deliberate choice — indented code blocks can't be accidentally terminated by anything in the pasted content, and they survive being pasted into GitHub's editor cleanly. The tradeoff is that they lose syntax highlighting. If you'd prefer the `lua` fences back for the highlighting, say the word and I'll produce a version using 4-backtick outer fences with 3-backtick inner fences, which also works.
