'use strict';

/**
 * Public API for Project AEGIS (Phase 2).
 *
 * Phase 1 exports (Task, Storage, Audit, Logger, Memory, Agent, ...)
 * are all preserved. Phase 2 adds:
 *   - providers  (offline + http, with a router)
 *   - tools      (default-deny registry)
 *   - budget     (per-task and global)
 *   - manifest   (agent declarations)
 *   - orchestrator (runs agents under declared limits)
 *   - recovery   (checkpoints, idempotency, cancellation)
 *   - config     (typed config, secrets stripped)
 */

const path = require('node:path');
const { Storage } = require('./storage');
const { Audit } = require('./audit');
const { Logger } = require('./log');
const { Memory } = require('./memory');
const { Agent, AgentRegistry, buildDefaultRegistry } = require('./agent');
const { Task } = require('./task');
const { STATES, isTerminal, canTransition } = require('./states');
const { dispatch, COMMANDS, help } = require('./router');

// Phase 2
const { OfflineProvider } = require('./providers/offline');
const { HttpProvider } = require('./providers/http');
const { ProviderRegistry, ProviderRouter } = require('./providers/registry');
const { ProviderError } = require('./providers/base');
const { ToolRegistry, buildDefaultRegistry: buildDefaultTools } = require('./tools/registry');
const { Budget, BudgetManager } = require('./usage');
const { Manifest, Orchestrator, buildDefaultManifest, synthesiseDeclaration } = require('./orchestrator');
const specialists = require('./specialists');
const { Checkpoint, CheckpointStore, Idempotency } = require('./recovery');
const { loadConfig, validateConfig, DEFAULTS } = require('./config');

function createContext(opts = {}) {
  const root = opts.root || process.cwd();
  const stateDir = opts.stateDir || path.join(root, 'state');
  const logDir = opts.logDir || path.join(root, 'logs');
  const dataDir = opts.dataDir || path.join(root, 'data');
  const memoryDir = path.join(dataDir, 'memory');
  const auditPath = opts.auditPath || path.join(logDir, 'audit.log');
  const logPath = opts.logPath || path.join(logDir, 'aegis.log');

  const logger = opts.logger || new Logger({ minLevel: opts.logLevel || 'info', component: 'aegis' });
  const audit = new Audit(auditPath);
  const storage = new Storage(stateDir);
  const memory = new Memory(memoryDir);
  const agentRegistry = opts.agentRegistry || buildDefaultRegistry();
  const toolRegistry = opts.toolRegistry || buildDefaultTools();
  const providerRegistry = opts.providerRegistry || new ProviderRegistry();
  const config = opts.config || loadConfig(root, opts.env || process.env);
  const budgets = opts.budgets || new BudgetManager();
  const manifest = opts.manifest || buildDefaultManifest(agentRegistry);
  const checkpoints = opts.checkpoints || new CheckpointStore(stateDir);
  const providerRouter = new ProviderRouter({
    registry: providerRegistry,
    allowPaid: config.provider.allowPaid,
    env: opts.env || process.env,
  });
  const orchestrator = new Orchestrator({
    manifest, agentRegistry, toolRegistry, memory,
    budget: opts.budget || null, audit, providerRouter,
  });

  return {
    root, logger, audit, storage, memory, agentRegistry, toolRegistry,
    providerRegistry, providerRouter, config, budgets, manifest, orchestrator, checkpoints,
    argv: opts.argv || [],
    options: opts,
  };
}

module.exports = {
  // Phase 1 surface (unchanged)
  createContext,
  dispatch,
  help,
  Task,
  Storage,
  Audit,
  Logger,
  Memory,
  Agent,
  AgentRegistry,
  buildDefaultRegistry,
  STATES,
  isTerminal,
  canTransition,
  COMMANDS,

  // Phase 2 additions
  OfflineProvider,
  HttpProvider,
  ProviderRegistry,
  ProviderRouter,
  ProviderError,
  ToolRegistry,
  buildDefaultTools,
  Budget,
  BudgetManager,
  Manifest,
  Orchestrator,
  buildDefaultManifest,
  synthesiseDeclaration,
  specialists,
  Checkpoint,
  CheckpointStore,
  Idempotency,
  loadConfig,
  validateConfig,
  DEFAULTS,
};