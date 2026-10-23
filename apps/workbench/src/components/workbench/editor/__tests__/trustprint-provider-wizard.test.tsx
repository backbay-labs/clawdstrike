import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TrustprintProviderWizard } from "../trustprint-provider-wizard";
import type { ConnectionTestResult } from "@/lib/workbench/trustprint-connection";
import { secureStore } from "@/features/settings/secure-store";


const connectionMocks = vi.hoisted(() => ({
  testEmbeddingConnection: vi.fn<
    (url: string, key: string, model: string) => Promise<ConnectionTestResult>
  >(),
}));

vi.mock("@/lib/workbench/trustprint-connection", () => connectionMocks);

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
}));


const defaultConfig = {
  embedding_api_url: undefined as string | undefined,
  embedding_api_key: undefined as string | undefined,
  embedding_model: undefined as string | undefined,
};

function renderWizard(
  overrides: Partial<{
    config: typeof defaultConfig;
    onChange: () => void;
    compact: boolean;
  }> = {},
) {
  const onChange = overrides.onChange ?? vi.fn();
  return {
    onChange,
    ...render(
      <TrustprintProviderWizard
        config={overrides.config ?? defaultConfig}
        onChange={onChange}
        compact={overrides.compact ?? false}
      />,
    ),
  };
}


beforeEach(() => {
  vi.clearAllMocks();
  connectionMocks.testEmbeddingConnection.mockResolvedValue({
    success: true,
    latencyMs: 142,
    dimensions: 1536,
    modelName: "text-embedding-3-small",
  });
});

afterEach(async () => {
  vi.unstubAllGlobals();
  // The panel talks to the real secure store (in-memory fallback in jsdom),
  // so clear anything a test saved.
  await secureStore.delete("orcarouter_api_key");
  await secureStore.delete("orcarouter_credential_meta");
});

describe("TrustprintProviderWizard", () => {
  // ---- Step 1: Provider selection ----

  it("renders all 4 provider cards", () => {
    renderWizard();

    expect(screen.getByTestId("provider-card-openai")).toBeInTheDocument();
    expect(screen.getByTestId("provider-card-cohere")).toBeInTheDocument();
    expect(screen.getByTestId("provider-card-voyage")).toBeInTheDocument();
    expect(screen.getByTestId("provider-card-custom")).toBeInTheDocument();
  });

  it("renders the step 1 heading", () => {
    renderWizard();

    expect(screen.getByText("Choose Provider")).toBeInTheDocument();
  });

  it("selecting a provider highlights its card", async () => {
    const user = userEvent.setup();
    renderWizard();

    const openaiCard = screen.getByTestId("provider-card-openai");
    await user.click(openaiCard);

    // Selected card gets gold border
    expect(openaiCard.className).toContain("border-[#d4a84b]");
  });

  it("selecting Custom provider shows URL input", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByTestId("provider-card-custom"));

    expect(screen.getByPlaceholderText(/your-api\.example\.com/)).toBeInTheDocument();
  });

  it("Next button is disabled until a provider is selected", () => {
    renderWizard();

    const nextButton = screen.getByRole("button", { name: /next/i });
    expect(nextButton).toBeDisabled();
  });

  // ---- Step progression ----

  it("advances from step 1 to step 2 on Next", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));

    expect(screen.getByText("API Key & Model")).toBeInTheDocument();
  });

  it("advances from step 2 to step 3", async () => {
    const user = userEvent.setup();
    renderWizard();

    // Step 1: select provider
    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));

    // Step 2: fill key and model
    const keyInput = screen.getByTestId("api-key-input");
    await user.type(keyInput, "sk-test-12345678");

    // A model is auto-selected for OpenAI, so just click Next
    await user.click(screen.getByRole("button", { name: /next/i }));

    // The step 3 heading says "Test Connection"
    expect(screen.getByTestId("test-connection-button")).toBeInTheDocument();
  });

  it("Back button returns to previous step", async () => {
    const user = userEvent.setup();
    renderWizard();

    // Go to step 2
    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));

    expect(screen.getByText("API Key & Model")).toBeInTheDocument();

    // Go back
    await user.click(screen.getByRole("button", { name: /back/i }));

    expect(screen.getByText("Choose Provider")).toBeInTheDocument();
  });

  // ---- Step 2: Credentials ----

  it("API key input is password type by default", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));

    const keyInput = screen.getByTestId("api-key-input");
    expect(keyInput).toHaveAttribute("type", "password");
  });

  it("show/hide toggle reveals API key", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));

    const keyInput = screen.getByTestId("api-key-input");
    expect(keyInput).toHaveAttribute("type", "password");

    // Click show
    await user.click(screen.getByTitle("Show key"));
    expect(keyInput).toHaveAttribute("type", "text");

    // Click hide
    await user.click(screen.getByTitle("Hide key"));
    expect(keyInput).toHaveAttribute("type", "password");
  });

  it("shows model options for the selected provider", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));

    expect(screen.getByTestId("model-option-text-embedding-3-small")).toBeInTheDocument();
    expect(screen.getByTestId("model-option-text-embedding-3-large")).toBeInTheDocument();
    expect(screen.getByTestId("model-option-text-embedding-ada-002")).toBeInTheDocument();
  });

  it("model options show dimensions", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));

    // OpenAI has 1536 dims (x2) and 3072 dims (x1)
    const dims1536 = screen.getAllByText("1536 dims");
    expect(dims1536.length).toBe(2);
    expect(screen.getByText("3072 dims")).toBeInTheDocument();
  });

  it("Next is disabled on step 2 until key is entered", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));

    // Model is auto-selected but key is empty
    const nextButton = screen.getByRole("button", { name: /next/i });
    expect(nextButton).toBeDisabled();
  });

  it("custom provider shows free text model input", async () => {
    const user = userEvent.setup();
    renderWizard();

    // Select Custom
    await user.click(screen.getByTestId("provider-card-custom"));
    // Fill custom URL
    await user.type(
      screen.getByPlaceholderText(/your-api\.example\.com/),
      "https://my.api.com/embed",
    );
    await user.click(screen.getByRole("button", { name: /next/i }));

    // Should show free text input for model
    expect(screen.getByPlaceholderText("e.g., text-embedding-3-small")).toBeInTheDocument();
  });

  // ---- Step 3: Connection test ----

  it("shows Test Connection button on step 3", async () => {
    const user = userEvent.setup();
    renderWizard();

    // Navigate to step 3
    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));
    await user.type(screen.getByTestId("api-key-input"), "sk-test-12345678");
    await user.click(screen.getByRole("button", { name: /next/i }));

    expect(screen.getByTestId("test-connection-button")).toBeInTheDocument();
  });

  it("connection test shows loading then success result", async () => {
    const user = userEvent.setup();
    renderWizard();

    // Navigate to step 3
    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));
    await user.type(screen.getByTestId("api-key-input"), "sk-test-12345678");
    await user.click(screen.getByRole("button", { name: /next/i }));

    // Click test
    await user.click(screen.getByTestId("test-connection-button"));

    // Wait for result
    await waitFor(() => {
      expect(screen.getByTestId("test-result")).toBeInTheDocument();
    });

    const resultBox = screen.getByTestId("test-result");
    expect(within(resultBox).getByText("Connected!")).toBeInTheDocument();
    expect(within(resultBox).getByText(/text-embedding-3-small/)).toBeInTheDocument();
    expect(within(resultBox).getByText(/1536 dimensions/)).toBeInTheDocument();
    expect(within(resultBox).getByText(/142ms/)).toBeInTheDocument();

    // Save button appears after success
    expect(screen.getByTestId("save-config-button")).toBeInTheDocument();
  });

  it("connection test shows failure result", async () => {
    connectionMocks.testEmbeddingConnection.mockResolvedValueOnce({
      success: false,
      error: "401 Unauthorized — check your API key",
    });

    const user = userEvent.setup();
    renderWizard();

    // Navigate to step 3
    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));
    await user.type(screen.getByTestId("api-key-input"), "sk-bad-key");
    await user.click(screen.getByRole("button", { name: /next/i }));

    await user.click(screen.getByTestId("test-connection-button"));

    await waitFor(() => {
      expect(screen.getByTestId("test-result")).toBeInTheDocument();
    });

    const resultBox = screen.getByTestId("test-result");
    expect(within(resultBox).getByText("Connection failed")).toBeInTheDocument();
    expect(within(resultBox).getByText(/401 Unauthorized/)).toBeInTheDocument();
  });

  it("Save Configuration calls onChange with config values", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    renderWizard({ onChange });

    // Navigate through wizard
    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));
    await user.type(screen.getByTestId("api-key-input"), "sk-test-12345678");
    await user.click(screen.getByRole("button", { name: /next/i }));

    // Test + save
    await user.click(screen.getByTestId("test-connection-button"));
    await waitFor(() => {
      expect(screen.getByTestId("save-config-button")).toBeInTheDocument();
    });
    await user.click(screen.getByTestId("save-config-button"));

    expect(onChange).toHaveBeenCalledWith({
      embedding_api_url: "https://api.openai.com/v1/embeddings",
      embedding_api_key: "sk-test-12345678",
      embedding_model: "text-embedding-3-small",
    });
  });

  it("skip test also calls onChange to commit config", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    renderWizard({ onChange });

    // Navigate through wizard
    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));
    await user.type(screen.getByTestId("api-key-input"), "sk-test-12345678");
    await user.click(screen.getByRole("button", { name: /next/i }));

    // Skip test
    await user.click(screen.getByText(/skip test/i));

    expect(onChange).toHaveBeenCalledWith({
      embedding_api_url: "https://api.openai.com/v1/embeddings",
      embedding_api_key: "sk-test-12345678",
      embedding_model: "text-embedding-3-small",
    });
  });

  // ---- Compact mode ----

  it("compact mode shows single row with Configure button", () => {
    renderWizard({ compact: true });

    const compactView = screen.getByTestId("compact-view");
    expect(compactView).toBeInTheDocument();
    expect(screen.getByText("Configure")).toBeInTheDocument();
  });

  it("compact mode shows provider name from config", () => {
    renderWizard({
      compact: true,
      config: {
        embedding_api_url: "https://api.openai.com/v1/embeddings",
        embedding_api_key: "sk-test",
        embedding_model: "text-embedding-3-small",
      },
    });

    expect(screen.getByText("OpenAI")).toBeInTheDocument();
    expect(screen.getByText("text-embedding-3-small")).toBeInTheDocument();
  });

  it("compact Configure button expands to full wizard", async () => {
    const user = userEvent.setup();
    renderWizard({ compact: true });

    await user.click(screen.getByText("Configure"));

    expect(screen.getByTestId("trustprint-provider-wizard")).toBeInTheDocument();
    expect(screen.getByText("Choose Provider")).toBeInTheDocument();
  });

  it("compact mode shows None when no provider configured", () => {
    renderWizard({ compact: true });

    expect(screen.getByText("None")).toBeInTheDocument();
  });

  // ---- Selecting provider updates URL ----

  it("selecting OpenAI auto-fills the URL", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    renderWizard({ onChange });

    await user.click(screen.getByTestId("provider-card-openai"));
    await user.click(screen.getByRole("button", { name: /next/i }));
    await user.type(screen.getByTestId("api-key-input"), "sk-test-12345678");
    await user.click(screen.getByRole("button", { name: /next/i }));

    // Step 3 summary shows the OpenAI URL
    expect(screen.getByText("https://api.openai.com/v1/embeddings")).toBeInTheDocument();
  });

  it("selecting Cohere auto-fills the Cohere URL", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByTestId("provider-card-cohere"));
    await user.click(screen.getByRole("button", { name: /next/i }));
    await user.type(screen.getByTestId("api-key-input"), "co-test-12345678");
    // Select a model
    await user.click(screen.getByTestId("model-option-embed-english-v3.0"));
    await user.click(screen.getByRole("button", { name: /next/i }));

    expect(screen.getByText("https://api.cohere.ai/v1/embed")).toBeInTheDocument();
  });

  // ---- Step indicator ----

  it("renders step indicator with 3 steps", () => {
    renderWizard();

    expect(screen.getByText("Provider")).toBeInTheDocument();
    expect(screen.getByText("Credentials")).toBeInTheDocument();
    expect(screen.getByText("Test")).toBeInTheDocument();
  });
});

// ---- OrcaRouter Cyber Inference ----

const ORCAROUTER_CATALOG = {
  data: [
    {
      id: "orcarouter/auto",
      name: "OrcaRouter Auto",
      supported_endpoint_types: ["openai"],
      architecture: { input_modalities: ["text"] },
    },
    {
      id: "text-embedding-3-small",
      name: "text-embedding-3-small",
      supported_endpoint_types: ["openai", "embeddings"],
      architecture: { input_modalities: ["text"] },
    },
  ],
};

function stubOrcaRouterFetch() {
  const fetchFn = vi.fn<typeof fetch>(async (input) => {
    const url = String(input);
    if (url.endsWith("/models")) {
      return new Response(JSON.stringify(ORCAROUTER_CATALOG), { status: 200 });
    }
    if (url.endsWith("/embeddings")) {
      return new Response(
        JSON.stringify({ data: [{ embedding: [0.1, 0.2, 0.3], index: 0 }], model: "orcarouter/auto" }),
        { status: 200 },
      );
    }
    return new Response("{}", { status: 200 });
  });
  vi.stubGlobal("fetch", fetchFn);
  return fetchFn;
}

async function connectViaApiKey(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByTestId("provider-card-orcarouter"));
  await user.click(screen.getByRole("button", { name: /next/i }));
  await user.type(screen.getByTestId("orcarouter-api-key-input"), "sk-orca-wizardkey123456");
  await user.click(screen.getByTestId("orcarouter-save-key"));
  await waitFor(() =>
    expect(screen.getByTestId("orcarouter-masked-key")).toBeInTheDocument(),
  );
}

describe("TrustprintProviderWizard — OrcaRouter Cyber Inference", () => {
  it("offers OrcaRouter as a named provider with the required display name", () => {
    renderWizard();
    const card = screen.getByTestId("provider-card-orcarouter");
    expect(card).toHaveTextContent("OrcaRouter Cyber Inference");
    expect(card).toHaveTextContent(/Cyber inference gateway/);
  });

  it("step 2 shows API key and Connect with OrcaRouter, not a free-text model box", async () => {
    stubOrcaRouterFetch();
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByTestId("provider-card-orcarouter"));
    await user.click(screen.getByRole("button", { name: /next/i }));

    expect(screen.getByTestId("orcarouter-auth-tab-api-key")).toBeInTheDocument();
    expect(screen.getByTestId("orcarouter-auth-tab-pkce")).toHaveTextContent(/Connect with OrcaRouter/);
    // Models are catalogue-driven; no free-text model entry for OrcaRouter.
    expect(screen.queryByPlaceholderText("e.g., text-embedding-3-small")).not.toBeInTheDocument();
    expect(screen.getByTestId("orcarouter-next")).toBeDisabled();
  });

  it("commits embedding_* and llm_* config from the OrcaRouter catalogue selection", async () => {
    const fetchFn = stubOrcaRouterFetch();
    const user = userEvent.setup();
    const onChange = vi.fn();
    renderWizard({ onChange });

    await connectViaApiKey(user);

    await user.click(await screen.findByTestId("orcarouter-embedding-model-trigger"));
    await user.click(
      screen.getByTestId("orcarouter-embedding-model-option-text-embedding-3-small"),
    );
    await user.click(screen.getByTestId("orcarouter-chat-model-trigger"));
    await user.click(screen.getByTestId("orcarouter-chat-model-option-orcarouter/auto"));

    await waitFor(() => expect(screen.getByTestId("orcarouter-next")).not.toBeDisabled());
    await user.click(screen.getByTestId("orcarouter-next"));

    await user.click(screen.getByText(/skip test/i));

    expect(onChange).toHaveBeenCalledWith({
      embedding_api_url: "https://api.orcarouter.ai/v1/embeddings",
      embedding_api_key: "sk-orca-wizardkey123456",
      embedding_model: "text-embedding-3-small",
      llm_api_url: "https://api.orcarouter.ai/v1/chat/completions",
      llm_api_key: "sk-orca-wizardkey123456",
      llm_model: "orcarouter/auto",
    });
    expect(fetchFn).toHaveBeenCalledWith(
      "https://api.orcarouter.ai/v1/models",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer sk-orca-wizardkey123456" }),
      }),
    );
  });

  it("runs the connection test through the OrcaRouter client", async () => {
    stubOrcaRouterFetch();
    const user = userEvent.setup();
    renderWizard();

    await connectViaApiKey(user);
    await user.click(await screen.findByTestId("orcarouter-embedding-model-trigger"));
    await user.click(
      screen.getByTestId("orcarouter-embedding-model-option-text-embedding-3-small"),
    );
    await waitFor(() => expect(screen.getByTestId("orcarouter-next")).not.toBeDisabled());
    await user.click(screen.getByTestId("orcarouter-next"));

    await user.click(screen.getByTestId("test-connection-button"));
    await waitFor(() => expect(screen.getByTestId("test-result")).toBeInTheDocument());
    expect(within(screen.getByTestId("test-result")).getByText("Connected!")).toBeInTheDocument();
  });

  it("keeps the deep-path LLM config out when no reasoning model is chosen", async () => {
    stubOrcaRouterFetch();
    const user = userEvent.setup();
    const onChange = vi.fn();
    renderWizard({ onChange });

    await connectViaApiKey(user);
    await user.click(await screen.findByTestId("orcarouter-embedding-model-trigger"));
    await user.click(
      screen.getByTestId("orcarouter-embedding-model-option-text-embedding-3-small"),
    );
    await waitFor(() => expect(screen.getByTestId("orcarouter-next")).not.toBeDisabled());
    await user.click(screen.getByTestId("orcarouter-next"));
    await user.click(screen.getByText(/skip test/i));

    const calls = onChange.mock.calls;
    const committed = calls[calls.length - 1]?.[0] as Record<string, unknown>;
    expect(committed.embedding_model).toBe("text-embedding-3-small");
    expect(committed).not.toHaveProperty("llm_model");
    expect(committed).not.toHaveProperty("llm_api_key");
  });
});
