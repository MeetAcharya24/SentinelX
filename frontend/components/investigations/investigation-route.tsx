"use client";

import { useParams } from "next/navigation";
import { InvestigationView } from "@/components/investigations/investigation-view";

export function InvestigationRoute() {
  const { id } = useParams<{ id: string }>();
  return <InvestigationView id={Number(id)} />;
}
