local channel = require("subspace.channel")
local transcription = require("subspace.transcription")
local synthesis = require("subspace.synthesis")
local playback = require("subspace.playback")
local log = require("subspace.log")

local MODES = {
    ECHO = true,
    DELAYED_ECHO = true,
    STT = true,
    TTS = true,
    STT_TTS = true,
}

local MODE_DEPENDENCIES = {
    ECHO = { "audio.playback" },
    DELAYED_ECHO = { "audio.playback" },
    STT = { "audio.transcription" },
    TTS = { "audio.synthesis", "audio.playback" },
    STT_TTS = { "audio.transcription", "audio.synthesis", "audio.playback" },
}

local mode = nil

local function application_failure(code, detail)
    return { error = { code = code, detail = detail } }
end

local function operation_failure(err)
    if type(err) ~= "table" or type(err.error) ~= "string" or err.error == "" then
        return application_failure("E_HOST_FAILURE", "audio operation failed")
    end
    local detail = err.reason
    if type(detail) ~= "string" or detail == "" then
        detail = "audio operation failed"
    end
    return application_failure(err.error, detail)
end

local function exact_keys(value, required)
    for key in pairs(value) do
        if not required[key] then
            return false
        end
    end
    for key in pairs(required) do
        if value[key] == nil then
            return false
        end
    end
    return true
end

local function startup(configuration)
    if type(configuration) ~= "table" or not exact_keys(configuration, { schema_version = true, values = true }) then
        return application_failure("E_INVALID_ARGUMENT", "invalid configuration")
    end
    if configuration.schema_version ~= 1 or type(configuration.values) ~= "table" then
        return application_failure("E_INVALID_ARGUMENT", "invalid configuration")
    end
    if not exact_keys(configuration.values, { mode = true }) then
        return application_failure("E_INVALID_ARGUMENT", "invalid configuration")
    end
    local configured_mode = configuration.values.mode
    if type(configured_mode) ~= "string" or not MODES[configured_mode] then
        return application_failure("E_INVALID_ARGUMENT", "invalid mode")
    end
    mode = configured_mode
end

local function handle_readiness(context)
    if mode == nil or type(context) ~= "table" or type(context.capabilities) ~= "table" then
        return { ready = false, status = mode or "" }
    end
    local capabilities = context.capabilities
    local dependencies = MODE_DEPENDENCIES[mode]
    for index = 1, #dependencies do
        if capabilities[dependencies[index]] ~= "available" then
            return { ready = false, status = mode }
        end
    end
    return { ready = true, status = mode }
end

local function handle_input(event)
    if type(event) ~= "table" or event.event ~= channel.CAPTURE_COMPLETE or event.audio == nil then
        return application_failure("E_INVALID_ARGUMENT", "invalid capture event")
    end

    if mode == "ECHO" or mode == "DELAYED_ECHO" then
        local delay = mode == "DELAYED_ECHO" and 5.0 or 0
        local scheduled, err = playback.schedule(event.audio, { delay_seconds = delay })
        if scheduled == nil then
            return operation_failure(err)
        end
        if type(scheduled) ~= "table" or scheduled.status ~= "scheduled" then
            return application_failure("E_HOST_FAILURE", "playback was not scheduled")
        end
        return { ok = true }
    end

    if mode == "STT" then
        local transcript, err = transcription.transcribe(event.audio)
        if transcript == nil then
            return operation_failure(err)
        end
        if type(transcript) ~= "table" or type(transcript.text) ~= "string" then
            return application_failure("E_HOST_FAILURE", "transcription returned invalid text")
        end
        local logged, log_error = log.info({ event = "transcript", text = transcript.text })
        if logged == nil and log_error ~= nil then
            return operation_failure(log_error)
        end
        return { ok = true }
    end

    if mode == "TTS" then
        local audio, err = synthesis.synthesize({
            text = "Debug synthesis test",
            language = "en",
            voice = "default",
            speed = 1.0,
        })
        if audio == nil then
            return operation_failure(err)
        end
        local scheduled, schedule_error = playback.schedule(audio, { delay_seconds = 0 })
        if scheduled == nil then
            return operation_failure(schedule_error)
        end
        if type(scheduled) ~= "table" or scheduled.status ~= "scheduled" then
            return application_failure("E_HOST_FAILURE", "playback was not scheduled")
        end
        return { ok = true }
    end

    if mode == "STT_TTS" then
        local transcript, transcription_error = transcription.transcribe(event.audio)
        if transcript == nil then
            return operation_failure(transcription_error)
        end
        if type(transcript) ~= "table" or type(transcript.text) ~= "string" then
            return application_failure("E_HOST_FAILURE", "transcription returned invalid text")
        end
        local audio, synthesis_error = synthesis.synthesize({
            text = transcript.text,
            language = "en",
            voice = "default",
            speed = 1.0,
        })
        if audio == nil then
            return operation_failure(synthesis_error)
        end
        local scheduled, playback_error = playback.schedule(audio, { delay_seconds = 0 })
        if scheduled == nil then
            return operation_failure(playback_error)
        end
        if type(scheduled) ~= "table" or scheduled.status ~= "scheduled" then
            return application_failure("E_HOST_FAILURE", "playback was not scheduled")
        end
        return { ok = true }
    end

    return application_failure("E_INVALID_ARGUMENT", "mode is not configured")
end

return {
    startup = startup,
    handle_readiness = handle_readiness,
    handle_input = handle_input,
}
