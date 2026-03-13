import { type ReactElement } from "react";
import { render, type RenderOptions } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { MultiPolicyProvider as WorkbenchProvider } from "@/lib/workbench/multi-policy-store";
import { FleetConnectionProvider } from "@/lib/workbench/use-fleet-connection";
import { GeneralSettingsProvider } from "@/lib/workbench/use-general-settings";
import { HintSettingsProvider } from "@/lib/workbench/use-hint-settings";
import { SentinelProvider } from "@/lib/workbench/sentinel-store";
import { FindingProvider } from "@/lib/workbench/finding-store";
import { OperatorProvider } from "@/lib/workbench/operator-store";
import { ToastProvider } from "@/components/ui/toast";

interface ProviderOptions extends Omit<RenderOptions, "wrapper"> {
  route?: string;
  routes?: string[];
}

/**
 * Renders a component wrapped in MemoryRouter + WorkbenchProvider.
 *
 * @param ui       - The React element to render
 * @param options  - route: initial route path; routes: initial entries array
 */
export function renderWithProviders(
  ui: ReactElement,
  { route = "/", routes, ...renderOptions }: ProviderOptions = {},
) {
  const initialEntries = routes ?? [route];

  function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <MemoryRouter initialEntries={initialEntries}>
        <OperatorProvider>
          <ToastProvider>
            <GeneralSettingsProvider>
              <HintSettingsProvider>
                <FleetConnectionProvider>
                  <WorkbenchProvider>
                    <SentinelProvider>
                      <FindingProvider>{children}</FindingProvider>
                    </SentinelProvider>
                  </WorkbenchProvider>
                </FleetConnectionProvider>
              </HintSettingsProvider>
            </GeneralSettingsProvider>
          </ToastProvider>
        </OperatorProvider>
      </MemoryRouter>
    );
  }

  return render(ui, { wrapper: Wrapper, ...renderOptions });
}
