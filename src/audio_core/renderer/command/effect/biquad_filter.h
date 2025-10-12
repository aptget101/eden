// SPDX-FileCopyrightText: Copyright 2025 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

// SPDX-FileCopyrightText: Copyright 2022 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <string>

#include "audio_core/renderer/command/icommand.h"
#include "audio_core/renderer/voice/voice_info.h"
#include "audio_core/renderer/voice/voice_state.h"
#include "common/common_types.h"

namespace AudioCore::ADSP::AudioRenderer {
class CommandListProcessor;
}

namespace AudioCore::Renderer {

/**
 * AudioRenderer command for applying a biquad filter to the input mix buffer, saving the results to
 * the output mix buffer.
 */
struct BiquadFilterCommand : ICommand {
    /**
     * Print this command's information to a string.
     *
     * @param processor - The CommandListProcessor processing this command.
     * @param string    - The string to print into.
     */
    void Dump(const AudioRenderer::CommandListProcessor& processor, std::string& string) override;

    /**
     * Process this command.
     *
     * @param processor - The CommandListProcessor processing this command.
     */
    void Process(const AudioRenderer::CommandListProcessor& processor) override;

    /**
     * Verify this command's data is valid.
     *
     * @param processor - The CommandListProcessor processing this command.
     * @return True if the command is valid, otherwise false.
     */
    bool Verify(const AudioRenderer::CommandListProcessor& processor) override;

    /// Input mix buffer index
    s16 input;
    /// Output mix buffer index
    s16 output;
    /// Input parameters for biquad
    VoiceInfo::BiquadFilterParameter biquad;
    /// Input parameters for biquad (REV15+ native float)
    VoiceInfo::BiquadFilterParameter2 biquad_float;
    /// Biquad state, updated each call
    CpuAddr state;
    /// If true, reset the state
    bool needs_init;
    /// If true, use float processing rather than int
    bool use_float_processing;
    /// If true, use native float coefficients (REV15+)
    bool use_float_coefficients;
};

/**
 * Biquad filter float implementation.
 *
 * @param output       - Output container for filtered samples.
 * @param input        - Input container for samples to be filtered.
 * @param b            - Feedforward coefficients.
 * @param a            - Feedback coefficients.
 * @param state        - State to track previous samples.
 * @param sample_count - Number of samples to process.
 */
void ApplyBiquadFilterFloat(std::span<s32> output, std::span<const s32> input,
                            std::array<s16, 3>& b, std::array<s16, 2>& a,
                            VoiceState::BiquadFilterState& state, const u32 sample_count);

/**
 * Biquad filter float implementation with native float coefficients (SDK REV15+).
 *
 * @param output       - Output container for filtered samples.
 * @param input        - Input container for samples to be filtered.
 * @param b            - Feedforward coefficients (float).
 * @param a            - Feedback coefficients (float).
 * @param state        - State to track previous samples.
 * @param sample_count - Number of samples to process.
 */
void ApplyBiquadFilterFloat2(std::span<s32> output, std::span<const s32> input,
                             std::array<f32, 3>& b, std::array<f32, 2>& a,
                             VoiceState::BiquadFilterState& state, const u32 sample_count);

} // namespace AudioCore::Renderer
