"use client";

import { useEffect } from "react";
import LogRocket from "logrocket";

export function Tracking() {
  useEffect(() => {
    LogRocket.init("fake-org/focusboard");
  }, []);
  return null;
}
