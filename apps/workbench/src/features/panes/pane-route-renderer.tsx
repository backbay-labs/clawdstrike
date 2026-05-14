import { useRoutes } from "react-router-dom";
import { WORKBENCH_ROUTE_OBJECTS, normalizeWorkbenchRoute } from "@/components/desktop/workbench-routes";

export function PaneRouteRenderer({ route }: { route: string }) {
  const element = useRoutes(WORKBENCH_ROUTE_OBJECTS, normalizeWorkbenchRoute(route));
  return element;
}
