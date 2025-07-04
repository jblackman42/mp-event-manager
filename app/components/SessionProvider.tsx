'use client';

import { createContext, useContext, ReactNode } from 'react';
import { SessionData } from '@/app/lib/oauth';

const SessionContext = createContext<SessionData | null>(null);

export function useSession() {
  const session = useContext(SessionContext);
  return session;
}

export function SessionProvider({ 
  children, 
  sessionData 
}: { 
  children: ReactNode; 
  sessionData: SessionData | null; 
}) {
  return (
    <SessionContext.Provider value={sessionData}>
      {children}
    </SessionContext.Provider>
  );
} 