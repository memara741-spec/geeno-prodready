export type Database = {
  public: {
    Tables: {
      profiles: { Row: { id: string; full_name: string | null; email: string | null; phone: string | null; role: string | null } };
      listings: { Row: { id: string; user_id: string; title: string; price: number; created_at: string } };
      orders: { Row: { id: string; buyer_id: string; listing_id: string; total: number; status: string } };
      messages: { Row: { id: string; sender_id: string; recipient_id: string; body: string } };
      accounts: { Row: { user_id: string; plan: string; is_admin: boolean; credits: number } };
    };
  };
};
