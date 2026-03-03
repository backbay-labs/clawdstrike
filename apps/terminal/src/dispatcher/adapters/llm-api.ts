/**
 * Shared LLM API call utilities for adapter modules.
 *
 * Eliminates duplication of Anthropic / OpenAI fetch logic across adapters
 * while allowing each adapter to customise model, system prompt, and error detail.
 */

import type { AdapterResult } from "../index"

export interface AnthropicCallOptions {
  apiKey: string
  model: string
  systemPrompt: string
  userContent: string
  signal: AbortSignal
  startTime: number
  maxTokens?: number
  includeErrorBody?: boolean
}

export interface OpenAiCallOptions {
  apiKey: string
  model: string
  systemPrompt: string
  userContent: string
  signal: AbortSignal
  startTime: number
  maxTokens?: number
  includeErrorBody?: boolean
}

export async function callAnthropicApi(
  opts: AnthropicCallOptions
): Promise<AdapterResult> {
  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": opts.apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: opts.model,
      max_tokens: opts.maxTokens ?? 8192,
      system: opts.systemPrompt,
      messages: [{ role: "user", content: opts.userContent }],
    }),
    signal: opts.signal,
  })

  if (!response.ok) {
    const detail = opts.includeErrorBody ? ` - ${await response.text()}` : ""
    return {
      success: false,
      output: "",
      error: `Anthropic API error: ${response.status}${detail}`,
    }
  }

  const data = (await response.json()) as {
    content?: { text?: string }[]
    model?: string
    usage?: { input_tokens?: number; output_tokens?: number }
  }

  return {
    success: true,
    output: data.content?.[0]?.text || "",
    telemetry: {
      model: data.model,
      tokens: data.usage
        ? { input: data.usage.input_tokens || 0, output: data.usage.output_tokens || 0 }
        : undefined,
      startedAt: opts.startTime,
      completedAt: Date.now(),
    },
  }
}

export async function callOpenAiApi(
  opts: OpenAiCallOptions
): Promise<AdapterResult> {
  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${opts.apiKey}`,
    },
    body: JSON.stringify({
      model: opts.model,
      messages: [
        { role: "system", content: opts.systemPrompt },
        { role: "user", content: opts.userContent },
      ],
      max_tokens: opts.maxTokens ?? 8192,
    }),
    signal: opts.signal,
  })

  if (!response.ok) {
    const detail = opts.includeErrorBody ? ` - ${await response.text()}` : ""
    return {
      success: false,
      output: "",
      error: `OpenAI API error: ${response.status}${detail}`,
    }
  }

  const data = (await response.json()) as {
    choices?: { message?: { content?: string } }[]
    model?: string
    usage?: { prompt_tokens?: number; completion_tokens?: number }
  }

  return {
    success: true,
    output: data.choices?.[0]?.message?.content || "",
    telemetry: {
      model: data.model,
      tokens: data.usage
        ? { input: data.usage.prompt_tokens || 0, output: data.usage.completion_tokens || 0 }
        : undefined,
      startedAt: opts.startTime,
      completedAt: Date.now(),
    },
  }
}
