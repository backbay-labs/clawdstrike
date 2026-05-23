import { useSentinels } from "@/features/sentinels/stores/sentinel-store";
import { SentinelList } from "../sentinels/sentinel-list";

export function SentinelsPage() {
  const { sentinels } = useSentinels();
  return <SentinelList sentinels={sentinels} />;
}

export default SentinelsPage;
