import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";

// Admin page: hidden from the menu for normal users.
const Admin = () => {
  const navigate = useNavigate();
  const [orders, setOrders] = useState<any[]>([]);

  useEffect(() => {
    const check = async () => {
      const { data: auth } = await supabase.auth.getUser();
      const { data: profile } = await supabase.from("profiles").select("role").eq("id", auth.user?.id).single();
      if (profile?.role !== "admin") {
        navigate("/");
        return;
      }
      const { data } = await supabase.from("orders").select("*");
      setOrders(data || []);
    };
    check();
  }, [navigate]);

  return <pre>{JSON.stringify(orders, null, 2)}</pre>;
};

export default Admin;
