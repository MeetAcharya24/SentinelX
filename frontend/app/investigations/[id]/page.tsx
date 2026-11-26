import { Suspense } from "react";
import { InvestigationRoute } from "@/components/investigations/investigation-route";
import { LoadingRows } from "@/components/ui/query-view";

export default function InvestigationPage() {
  return (
    <Suspense fallback={<LoadingRows rows={6} />}>
      <InvestigationRoute />
    </Suspense>
  );
}
