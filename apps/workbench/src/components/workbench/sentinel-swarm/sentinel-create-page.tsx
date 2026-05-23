import { useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useSentinels } from "@/features/sentinels/stores/sentinel-store";
import { SentinelCreate } from "../sentinels/sentinel-create";

export function SentinelCreatePage() {
  const { createSentinel } = useSentinels();
  const navigate = useNavigate();
  const handleCreated = useCallback(() => {
    navigate("/sentinels");
  }, [navigate]);
  return <SentinelCreate onCreated={handleCreated} createFn={createSentinel} />;
}

export default SentinelCreatePage;
