-- ============================================================================
-- 0BULLSHIT BACKEND V2.0 - SUPABASE SCHEMA
-- Sistema completo de usuarios, créditos, bots y memoria neuronal
-- ============================================================================

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- USERS & AUTHENTICATION
-- ============================================================================

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    plan VARCHAR(20) DEFAULT 'free' CHECK (plan IN ('free', 'growth', 'pro')),
    credits_balance INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT true,
    is_admin BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Subscriptions table
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    plan VARCHAR(20) NOT NULL CHECK (plan IN ('growth', 'pro')),
    stripe_subscription_id VARCHAR(255) UNIQUE,
    stripe_customer_id VARCHAR(255),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'cancelled', 'past_due', 'unpaid')),
    current_period_start TIMESTAMP WITH TIME ZONE,
    current_period_end TIMESTAMP WITH TIME ZONE,
    cancel_at_period_end BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id)
);

-- Credit transactions log
CREATE TABLE credit_transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    amount INTEGER NOT NULL, -- Positive for additions, negative for charges
    transaction_type VARCHAR(20) NOT NULL CHECK (transaction_type IN ('add', 'charge', 'bonus', 'refund')),
    description TEXT,
    bot_used VARCHAR(100),
    stripe_payment_intent_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- BOT SYSTEM & NEURAL MEMORY
-- ============================================================================

-- Neural memory main storage
CREATE TABLE neural_memory (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    memory_type VARCHAR(50) DEFAULT 'main_memory',
    memory_data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, memory_type)
);

-- Bot interactions log
CREATE TABLE neural_interactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    bot_used VARCHAR(100) NOT NULL,
    user_input TEXT NOT NULL,
    bot_output TEXT NOT NULL,
    credits_charged INTEGER DEFAULT 0,
    context_data JSONB DEFAULT '{}',
    success_rating INTEGER CHECK (success_rating BETWEEN 1 AND 5),
    session_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Bot usage statistics
CREATE TABLE bot_usage_stats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    bot_id VARCHAR(100) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    usage_count INTEGER DEFAULT 1,
    total_credits_spent INTEGER DEFAULT 0,
    average_rating DECIMAL(3,2),
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(bot_id, user_id)
);

-- ============================================================================
-- SEARCH SYSTEM (Growth/Pro plans)
-- ============================================================================

-- Investors database (your existing table)
CREATE TABLE IF NOT EXISTS investors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    "Company_Name" TEXT,
    "Company_Description" TEXT,
    "Investing_Stage" TEXT,
    "Company_Location" TEXT,
    "Investment_Categories" TEXT,
    "Company_Linkedin" TEXT,
    "Keywords_Ubicacion_Adicionales" TEXT,
    "Keywords_Etapas_Adicionales" TEXT,
    "Keywords_Categorias_Adicionales" TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Employees database (your existing table)
CREATE TABLE IF NOT EXISTS employees (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    "fullName" TEXT,
    "headline" TEXT,
    "current_job_title" TEXT,
    "location" TEXT,
    "linkedinUrl" TEXT,
    "email" TEXT,
    "profilePic" TEXT,
    "Company_Name" TEXT,
    "decision_score" INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Search history and preferences
CREATE TABLE search_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    search_type VARCHAR(20) CHECK (search_type IN ('investors', 'employees')),
    query TEXT NOT NULL,
    filters_used JSONB DEFAULT '{}',
    results_count INTEGER DEFAULT 0,
    credits_spent INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Saved entities (investors/employees)
CREATE TABLE saved_entities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    entity_id UUID NOT NULL,
    entity_type VARCHAR(20) CHECK (entity_type IN ('investor', 'employee')),
    sentiment VARCHAR(20) DEFAULT 'none' CHECK (sentiment IN ('like', 'dislike', 'none')),
    notes TEXT,
    tags TEXT[], -- Array of tags
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, entity_id, entity_type)
);

-- ============================================================================
-- OUTREACH SYSTEM (Pro plan only)
-- ============================================================================

-- Outreach templates
CREATE TABLE outreach_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    template_name VARCHAR(255) NOT NULL,
    target_type VARCHAR(20) CHECK (target_type IN ('investor', 'employee')),
    platform VARCHAR(20) CHECK (platform IN ('email', 'linkedin')),
    subject_line TEXT,
    template_content TEXT NOT NULL,
    variables_used JSONB DEFAULT '{}', -- Template variables
    usage_count INTEGER DEFAULT 0,
    success_rate DECIMAL(5,2) DEFAULT 0.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Outreach campaigns
CREATE TABLE outreach_campaigns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    campaign_name VARCHAR(255) NOT NULL,
    template_id UUID REFERENCES outreach_templates(id),
    target_list JSONB NOT NULL DEFAULT '[]', -- Array of target IDs
    status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'paused', 'completed')),
    messages_sent INTEGER DEFAULT 0,
    responses_received INTEGER DEFAULT 0,
    credits_spent INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Individual outreach messages
CREATE TABLE outreach_messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_id UUID REFERENCES outreach_campaigns(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    target_id UUID NOT NULL,
    target_type VARCHAR(20) CHECK (target_type IN ('investor', 'employee')),
    platform VARCHAR(20) CHECK (platform IN ('email', 'linkedin')),
    message_content TEXT NOT NULL,
    unipile_message_id VARCHAR(255), -- External API reference
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'delivered', 'opened', 'replied', 'failed')),
    sent_at TIMESTAMP WITH TIME ZONE,
    opened_at TIMESTAMP WITH TIME ZONE,
    replied_at TIMESTAMP WITH TIME ZONE,
    response_content TEXT,
    credits_charged INTEGER DEFAULT 5,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- GENERATED DOCUMENTS & CONTENT
-- ============================================================================

-- Documents generated by bots
CREATE TABLE generated_documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    bot_used VARCHAR(100) NOT NULL,
    document_type VARCHAR(50), -- 'pitch_deck', 'business_plan', 'market_analysis', etc.
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    format VARCHAR(20) DEFAULT 'markdown', -- 'markdown', 'html', 'pdf'
    metadata JSONB DEFAULT '{}',
    is_public BOOLEAN DEFAULT false,
    download_count INTEGER DEFAULT 0,
    credits_used INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Document versions (for iteration)
CREATE TABLE document_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_id UUID REFERENCES generated_documents(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL DEFAULT 1,
    content TEXT NOT NULL,
    changes_description TEXT,
    credits_used INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- ANALYTICS & PLATFORM STATS
-- ============================================================================

-- Platform usage analytics
CREATE TABLE platform_analytics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    date DATE NOT NULL DEFAULT CURRENT_DATE,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(15,2) NOT NULL,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(date, metric_name)
);

-- User activity sessions
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    session_end TIMESTAMP WITH TIME ZONE,
    actions_count INTEGER DEFAULT 0,
    credits_spent INTEGER DEFAULT 0,
    devices_info JSONB DEFAULT '{}',
    ip_address INET
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Users
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_plan ON users(plan);
CREATE INDEX idx_users_created_at ON users(created_at);

-- Subscriptions
CREATE INDEX idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);
CREATE INDEX idx_subscriptions_stripe_id ON subscriptions(stripe_subscription_id);

-- Credit transactions
CREATE INDEX idx_credit_transactions_user_id ON credit_transactions(user_id);
CREATE INDEX idx_credit_transactions_created_at ON credit_transactions(created_at);
CREATE INDEX idx_credit_transactions_type ON credit_transactions(transaction_type);

-- Neural system
CREATE INDEX idx_neural_memory_user_id ON neural_memory(user_id);
CREATE INDEX idx_neural_interactions_user_id ON neural_interactions(user_id);
CREATE INDEX idx_neural_interactions_bot ON neural_interactions(bot_used);
CREATE INDEX idx_neural_interactions_created_at ON neural_interactions(created_at);
CREATE INDEX idx_bot_usage_stats_user_id ON bot_usage_stats(user_id);
CREATE INDEX idx_bot_usage_stats_bot_id ON bot_usage_stats(bot_id);

-- Search system
CREATE INDEX idx_investors_company_name ON investors("Company_Name");
CREATE INDEX idx_employees_company_name ON employees("Company_Name");
CREATE INDEX idx_employees_decision_score ON employees("decision_score");
CREATE INDEX idx_search_history_user_id ON search_history(user_id);
CREATE INDEX idx_saved_entities_user_id ON saved_entities(user_id);

-- Outreach system
CREATE INDEX idx_outreach_templates_user_id ON outreach_templates(user_id);
CREATE INDEX idx_outreach_campaigns_user_id ON outreach_campaigns(user_id);
CREATE INDEX idx_outreach_messages_campaign_id ON outreach_messages(campaign_id);
CREATE INDEX idx_outreach_messages_status ON outreach_messages(status);

-- Documents
CREATE INDEX idx_generated_documents_user_id ON generated_documents(user_id);
CREATE INDEX idx_generated_documents_type ON generated_documents(document_type);
CREATE INDEX idx_document_versions_document_id ON document_versions(document_id);

-- Analytics
CREATE INDEX idx_platform_analytics_date ON platform_analytics(date);
CREATE INDEX idx_platform_analytics_metric ON platform_analytics(metric_name);
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);

-- ============================================================================
-- RLS (Row Level Security) POLICIES
-- ============================================================================

-- Enable RLS on user-specific tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE credit_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE neural_memory ENABLE ROW LEVEL SECURITY;
ALTER TABLE neural_interactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE bot_usage_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE search_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE outreach_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE outreach_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE outreach_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE generated_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;

-- Users can only see their own data
CREATE POLICY "Users can view own profile" ON users FOR SELECT USING (auth.uid()::text = id::text);
CREATE POLICY "Users can update own profile" ON users FOR UPDATE USING (auth.uid()::text = id::text);

-- Subscriptions
CREATE POLICY "Users can view own subscriptions" ON subscriptions FOR SELECT USING (auth.uid()::text = user_id::text);

-- Credit transactions
CREATE POLICY "Users can view own transactions" ON credit_transactions FOR SELECT USING (auth.uid()::text = user_id::text);

-- Neural memory
CREATE POLICY "Users can view own memory" ON neural_memory FOR ALL USING (auth.uid()::text = user_id::text);
CREATE POLICY "Users can view own interactions" ON neural_interactions FOR ALL USING (auth.uid()::text = user_id::text);

-- Search and outreach
CREATE POLICY "Users can view own searches" ON search_history FOR ALL USING (auth.uid()::text = user_id::text);
CREATE POLICY "Users can view own saved entities" ON saved_entities FOR ALL USING (auth.uid()::text = user_id::text);
CREATE POLICY "Users can view own outreach" ON outreach_templates FOR ALL USING (auth.uid()::text = user_id::text);
CREATE POLICY "Users can view own campaigns" ON outreach_campaigns FOR ALL USING (auth.uid()::text = user_id::text);
CREATE POLICY "Users can view own messages" ON outreach_messages FOR ALL USING (auth.uid()::text = user_id::text);

-- Documents
CREATE POLICY "Users can view own documents" ON generated_documents FOR ALL USING (auth.uid()::text = user_id::text);

-- ============================================================================
-- FUNCTIONS & TRIGGERS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply the trigger to tables that need it
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
CREATE TRIGGER update_subscriptions_updated_at BEFORE UPDATE ON subscriptions FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
CREATE TRIGGER update_neural_memory_updated_at BEFORE UPDATE ON neural_memory FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
CREATE TRIGGER update_bot_usage_stats_updated_at BEFORE UPDATE ON bot_usage_stats FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
CREATE TRIGGER update_saved_entities_updated_at BEFORE UPDATE ON saved_entities FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
CREATE TRIGGER update_outreach_templates_updated_at BEFORE UPDATE ON outreach_templates FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
CREATE TRIGGER update_outreach_campaigns_updated_at BEFORE UPDATE ON outreach_campaigns FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
CREATE TRIGGER update_generated_documents_updated_at BEFORE UPDATE ON generated_documents FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();

-- Function to automatically charge credits on bot usage
CREATE OR REPLACE FUNCTION log_bot_usage()
RETURNS TRIGGER AS $$
BEGIN
    -- Update or insert bot usage stats
    INSERT INTO bot_usage_stats (bot_id, user_id, usage_count, total_credits_spent, last_used_at, updated_at)
    VALUES (NEW.bot_used, NEW.user_id, 1, NEW.credits_charged, NEW.created_at, NEW.created_at)
    ON CONFLICT (bot_id, user_id)
    DO UPDATE SET
        usage_count = bot_usage_stats.usage_count + 1,
        total_credits_spent = bot_usage_stats.total_credits_spent + NEW.credits_charged,
        last_used_at = NEW.created_at,
        updated_at = NEW.created_at;
    
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to log bot usage automatically
CREATE TRIGGER log_bot_usage_trigger 
    AFTER INSERT ON neural_interactions 
    FOR EACH ROW EXECUTE PROCEDURE log_bot_usage();

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Insert initial platform analytics
INSERT INTO platform_analytics (date, metric_name, metric_value) VALUES
(CURRENT_DATE, 'total_users', 0),
(CURRENT_DATE, 'active_users_today', 0),
(CURRENT_DATE, 'total_credits_spent', 0),
(CURRENT_DATE, 'total_bot_interactions', 0);

-- ============================================================================
-- VIEWS FOR ANALYTICS
-- ============================================================================

-- User activity summary
CREATE VIEW user_activity_summary AS
SELECT 
    u.id,
    u.email,
    u.plan,
    u.credits_balance,
    u.created_at as user_since,
    COALESCE(ni.interaction_count, 0) as total_interactions,
    COALESCE(ct.total_spent, 0) as total_credits_spent,
    COALESCE(sh.search_count, 0) as total_searches,
    COALESCE(gd.document_count, 0) as documents_generated
FROM users u
LEFT JOIN (
    SELECT user_id, COUNT(*) as interaction_count
    FROM neural_interactions
    GROUP BY user_id
) ni ON u.id = ni.user_id
LEFT JOIN (
    SELECT user_id, SUM(ABS(amount)) as total_spent
    FROM credit_transactions
    WHERE transaction_type = 'charge'
    GROUP BY user_id
) ct ON u.id = ct.user_id
LEFT JOIN (
    SELECT user_id, COUNT(*) as search_count
    FROM search_history
    GROUP BY user_id
) sh ON u.id = sh.user_id
LEFT JOIN (
    SELECT user_id, COUNT(*) as document_count
    FROM generated_documents
    GROUP BY user_id
) gd ON u.id = gd.user_id;

-- Bot popularity view
CREATE VIEW bot_popularity AS
SELECT 
    bot_used,
    COUNT(*) as usage_count,
    COUNT(DISTINCT user_id) as unique_users,
    SUM(credits_charged) as total_credits_generated,
    AVG(success_rating) as avg_rating,
    MAX(created_at) as last_used
FROM neural_interactions
GROUP BY bot_used
ORDER BY usage_count DESC;

-- Revenue analytics view
CREATE VIEW revenue_analytics AS
SELECT 
    DATE_TRUNC('month', created_at) as month,
    plan,
    COUNT(*) as new_subscriptions,
    COUNT(*) * CASE 
        WHEN plan = 'growth' THEN 20
        WHEN plan = 'pro' THEN 89
        ELSE 0
    END as monthly_recurring_revenue
FROM subscriptions
WHERE status = 'active'
GROUP BY DATE_TRUNC('month', created_at), plan
ORDER BY month DESC, plan;

COMMENT ON SCHEMA public IS '0Bullshit Backend v2.0 - Complete database schema with users, bots, credits, search, outreach, and analytics';
