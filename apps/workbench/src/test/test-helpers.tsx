import { type ReactElement } from "react";
import { render, type RenderOptions } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { MultiPolicyProvider as WorkbenchProvider } from "@/lib/workbench/multi-policy-store";
import { FleetConnectionProvider } from "@/lib/workbench/use-fleet-connection";
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
        <ToastProvider>
          <FleetConnectionProvider>
            <WorkbenchProvider>{children}</WorkbenchProvider>
          </FleetConnectionProvider>
        </ToastProvider>
      </MemoryRouter>
    );
  }

  return render(ui, { wrapper: Wrapper, ...renderOptions });
}
