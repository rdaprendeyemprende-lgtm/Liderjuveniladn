-- 1. TABLA DE GRUPOS
CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    logo_url TEXT, -- Almacenará la URL del Storage o Base64
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 2. TABLA DE PERFILES (Extensión de auth.users de Supabase)
CREATE TABLE profiles (
    id UUID PRIMARY KEY REFERENCES auth.users ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    group_id UUID REFERENCES groups(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- 3. SECCIONES DE REQUISITOS
CREATE TABLE requirement_sections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    order_index INT DEFAULT 0
);

-- 4. REQUISITOS DEL PROGRAMA
CREATE TABLE requirements (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    section_id UUID REFERENCES requirement_sections(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    deadline DATE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 5. PARTICIPANTES
CREATE TABLE participants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    age INT,
    phone TEXT,
    email TEXT,
    church TEXT,
    enrollment_date DATE DEFAULT CURRENT_DATE,
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(group_id, name)
);

-- 6. COMPLETITUD DE REQUISITOS (Relación muchos a muchos)
CREATE TABLE completions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    participant_id UUID REFERENCES participants(id) ON DELETE CASCADE,
    requirement_id TEXT NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
    completion_date DATE DEFAULT CURRENT_DATE,
    completed_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(participant_id, requirement_id)
);

-- 7. OBSERVACIONES POR REQUISITO
CREATE TABLE observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    participant_id UUID REFERENCES participants(id) ON DELETE CASCADE,
    requirement_id TEXT REFERENCES requirements(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    date DATE DEFAULT CURRENT_DATE,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 8. CONFIGURACIÓN GLOBAL
CREATE TABLE settings (
    id INT PRIMARY KEY DEFAULT 1,
    program_name TEXT DEFAULT 'Programa de Liderazgo Juvenil',
    org_name TEXT,
    program_year TEXT DEFAULT '2026',
    CONSTRAINT only_one_row CHECK (id = 1)
);

-- ==========================================
-- SEGURIDAD: ROW LEVEL SECURITY (RLS)
-- ==========================================

-- Habilitar RLS en las tablas críticas
ALTER TABLE participants ENABLE ROW LEVEL SECURITY;
ALTER TABLE completions ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE requirement_sections ENABLE ROW LEVEL SECURITY;
ALTER TABLE requirements ENABLE ROW LEVEL SECURITY;

-- Política para Secciones: Todos ven, solo admin edita
CREATE POLICY "Sections are viewable by everyone" ON requirement_sections FOR SELECT USING (true);
CREATE POLICY "Admins can manage sections" ON requirement_sections
    FOR ALL TO authenticated USING ((SELECT role FROM public.profiles WHERE id = auth.uid()) = 'admin');

-- Política para Requisitos: Todos ven, solo admin edita
CREATE POLICY "Requirements are viewable by everyone" ON requirements FOR SELECT USING (true);
CREATE POLICY "Admins can manage requirements" ON requirements
    FOR ALL TO authenticated USING ((SELECT role FROM public.profiles WHERE id = auth.uid()) = 'admin');

-- Política: Los usuarios solo ven participantes de su propio grupo. Admins ven todos.
CREATE POLICY "Users can only access their group participants" ON participants
    FOR ALL USING (
        (SELECT role FROM public.profiles WHERE id = auth.uid()) = 'admin' OR
        group_id = (SELECT group_id FROM profiles WHERE id = auth.uid())
    ) WITH CHECK (
        (SELECT role FROM public.profiles WHERE id = auth.uid()) = 'admin' OR
        group_id = (SELECT group_id FROM profiles WHERE id = auth.uid())
    );
    
-- Política: Completitudes filtradas por acceso al participante (hereda de la política de participantes)
CREATE POLICY "Users can access completions of their group" ON completions
    FOR ALL 
    TO authenticated
    USING (
        EXISTS (
            SELECT 1 FROM participants 
            WHERE id = completions.participant_id
        )
    ) 
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM participants 
            WHERE id = completions.participant_id
        )
    );

-- Política: Observaciones filtradas por acceso al participante
CREATE POLICY "Users can access observations of their group" ON observations
    FOR ALL USING (
        EXISTS (SELECT 1 FROM participants WHERE id = observations.participant_id)
    ) WITH CHECK (
        EXISTS (SELECT 1 FROM participants WHERE id = observations.participant_id)
    );

-- Políticas para la tabla de Perfiles
CREATE POLICY "Profiles are viewable by authenticated users" ON profiles
    FOR SELECT TO authenticated USING (true);

CREATE POLICY "Users can update their own profile" ON profiles
    FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Admins can update all profiles" ON profiles
    FOR UPDATE USING ((SELECT role FROM public.profiles WHERE id = auth.uid()) = 'admin');

CREATE POLICY "Admins can delete all profiles" ON profiles
    FOR DELETE USING ((SELECT role FROM public.profiles WHERE id = auth.uid()) = 'admin');

-- Política para Settings: Todos pueden leer, solo admin edita
CREATE POLICY "Settings are viewable by everyone" ON settings FOR SELECT USING (true);
CREATE POLICY "Admins can manage settings" ON settings
    FOR ALL TO authenticated USING ((SELECT role FROM public.profiles WHERE id = auth.uid()) = 'admin');

-- Permitir que todos los usuarios autenticados puedan ver los grupos para que el sistema funcione correctamente
CREATE POLICY "Groups are viewable by authenticated users" ON groups
    FOR SELECT TO authenticated USING (true);

CREATE POLICY "Admins can manage groups" ON groups
    FOR INSERT, UPDATE, DELETE USING ((SELECT role FROM profiles WHERE id = auth.uid()) = 'admin');

-- ==========================================
-- 9. AUTOMATIZACIÓN DE PERFILES (TRIGGER)
-- ==========================================
-- Esta función crea automáticamente un perfil cada vez que un usuario se registra

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    is_admin BOOLEAN;
BEGIN
  -- Verificamos si es el admin principal (asegurando que no sea nulo)
  is_admin := (LOWER(COALESCE(NEW.email, '')) = 'ministrylion@gmail.com');

  INSERT INTO public.profiles (id, full_name, email, role)
  VALUES (
    NEW.id, 
    CASE 
        WHEN is_admin THEN 'Administrador Principal' 
        ELSE COALESCE(NEW.raw_user_meta_data->>'full_name', SPLIT_PART(NEW.email, '@', 1)) 
    END, 
    COALESCE(NEW.email, 'sin-email@sistema.com'), 
    CASE WHEN is_admin THEN 'admin' ELSE 'user' END
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ==========================================
-- INSERCIÓN DE DATOS INICIALES (SECCIONES)
-- ==========================================
INSERT INTO requirement_sections (name, order_index) VALUES 
('Comprobante de pago', 1),
('I. Pre-requisitos', 2),
('II. Usted y Dios', 3),
('III. Usted y Usted', 4),
('IV. Usted y los jóvenes', 5),
('V. Usted y la iglesia', 6),
('VI. Usted y la comunidad', 7),
('VII. Carpeta (documentación)', 8),
('Especialidades', 9),
('Encuentros presenciales', 10),
('Encuentros virtuales', 11);

-- Configuración por defecto
INSERT INTO settings (id, program_name, program_year) VALUES (1, 'Liderazgo JA', '2026');

-- ==========================================
-- 10. FUNCIÓN PARA ELIMINAR USUARIOS (ADMIN)
-- ==========================================
CREATE OR REPLACE FUNCTION public.delete_user_by_admin(target_user_id UUID)
RETURNS VOID AS $$
DECLARE
  _caller_uid UUID := auth.uid(); -- Capturamos el UID del usuario que llama una sola vez
  _caller_role TEXT;
BEGIN
  -- 1. Asegurarse de que el usuario que llama esté autenticado
  IF _caller_uid IS NULL THEN
    RAISE EXCEPTION 'Acceso denegado. No se pudo identificar al usuario que llama (no autenticado).';
  END IF;

  -- 2. Obtener el rol del usuario que está ejecutando la función
  SELECT role INTO _caller_role FROM public.profiles WHERE id = _caller_uid;

  -- 3. Verificar si el perfil del usuario que llama existe y tiene un rol
  IF _caller_role IS NULL THEN
    RAISE EXCEPTION 'Acceso denegado. Perfil no encontrado o rol no asignado para el usuario que llama (ID: %).', _caller_uid;
  END IF;

  -- 4. Verificar si es administrador
  IF _caller_role = 'admin' THEN
    -- 5. Intentar borrar de la tabla de autenticación
    DELETE FROM auth.users WHERE id = target_user_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'No se encontró el usuario con ID % en auth.users o no se pudo eliminar.', target_user_id;
    END IF;
  ELSE
    RAISE EXCEPTION 'Acceso denegado. Solo administradores pueden eliminar usuarios. Su rol es: %', _caller_role;
  END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;