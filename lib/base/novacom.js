/*
 * Copyright (c) 2020-2023 LG Electronics Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

const async = require('async'),
    chalk = require('chalk'),
    fs = require('fs'),
    mkdirp = require('mkdirp'),
    net = require('net'),
    log = require('npmlog'),
    path = require('path'),
    shelljs = require('shelljs'),
    stream = require('stream'),
    util = require('util'),
    os = require('os'),
    { spawn, execFileSync } = require('child_process'),
    Appdata = require('./cli-appdata'),
    errHndl = require('./error-handler'),
    server = require('./server');

// novacom emulation layer, on top of ssh
(function() {
    const novacom = {};

    log.heading = 'novacom';
    log.level = 'warn';
    novacom.log = log;

    const keydir = path.resolve(process.env.HOME || process.env.USERPROFILE, '.ssh');
    let cliData;

    // ---------------------------------------------------------------------------
    // System-ssh transport (replaces the bundled ssh2 JS library).
    //
    // Modern Node (18+) statically links OpenSSL 3, which refuses SHA-1 RSA
    // signatures outright. Legacy webOS TVs (webOS 1.x/2.x, ~2014-2015) only
    // offer ssh-rsa host keys and only accept ssh-rsa client-auth signatures,
    // so ssh2 fails the handshake with "signature verification failed" and no
    // JS-level algorithm tweak can help. The system `ssh`/`scp` binaries can
    // still do SHA-1, so we shell out to them. A per-process OpenSSL config
    // re-enables SHA-1 for the spawned ssh only -- the system-wide crypto
    // policy is never changed. On non-RHEL hosts and modern targets this is all
    // harmless (the legacy options are additive, the OpenSSL knob is a no-op).
    // ---------------------------------------------------------------------------

    let _opensslConfPath; // cached per process

    function opensslEnv() {
        const env = Object.assign({}, process.env);
        try {
            if (_opensslConfPath === undefined) {
                _opensslConfPath = null;
                let opensslDir = '';
                try {
                    opensslDir = execFileSync('openssl', ['version', '-d'], { encoding: 'utf8' })
                        .replace(/OPENSSLDIR:\s*"?([^"\n]*)"?/, '$1').trim();
                } catch (e) { opensslDir = ''; }
                const baseCnf = opensslDir ? path.join(opensslDir, 'openssl.cnf') : '';
                let content = '';
                if (baseCnf && fs.existsSync(baseCnf)) {
                    content += '.include ' + baseCnf + '\n';
                }
                content += '\n[openssl_init]\nalg_section = evp_properties\n' +
                           '\n[evp_properties]\nrh-allow-sha1-signatures = yes\n';
                const confPath = path.join(os.tmpdir(), 'ares-legacy-openssl.cnf');
                fs.writeFileSync(confPath, content);
                _opensslConfPath = confPath;
            }
            if (_opensslConfPath) {
                env.OPENSSL_CONF = _opensslConfPath;
            }
        } catch (e) {
            // best-effort: fall back to the default environment
        }
        return env;
    }

    // '+' prepends these to the client defaults, so modern targets still
    // negotiate strong algorithms and are unaffected.
    const LEGACY_SSH_OPTS = [
        '-o', 'HostKeyAlgorithms=+ssh-rsa',
        '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa',
        '-o', 'KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1',
        '-o', 'Ciphers=+aes128-cbc,3des-cbc,aes256-cbc',
        '-o', 'MACs=+hmac-sha1'
    ];

    function commonSshOpts(target, controlPath) {
        const opts = [
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-o', 'ConnectTimeout=30'
        ];
        if (controlPath) {
            opts.push('-o', 'ControlMaster=auto',
                      '-o', 'ControlPath=' + controlPath,
                      '-o', 'ControlPersist=60');
        }
        if (target.privateKeyName) {
            opts.push('-i', path.join(keydir, target.privateKeyName),
                      '-o', 'IdentitiesOnly=yes');
        }
        return opts.concat(LEGACY_SSH_OPTS);
    }

    // Spawn system ssh. `remoteCmd` null => no command (e.g. port-forward with
    // extraArgs). Falls back to sshpass -e for password auth when no key.
    function sshSpawn(target, remoteCmd, controlPath, extraArgs) {
        const env = opensslEnv();
        let file = 'ssh';
        let args = commonSshOpts(target, controlPath).concat(['-p', String(target.port)]);
        if (extraArgs) {
            args = args.concat(extraArgs);
        }
        args.push(target.username + '@' + target.host);
        if (remoteCmd != null) {
            args.push(remoteCmd);
        }
        if (target.password && !target.privateKeyName) {
            env.SSHPASS = target.password;
            args = ['-e', 'ssh'].concat(args);
            file = 'sshpass';
        }
        return spawn(file, args, { env: env });
    }

    function freePort(cb) {
        const srv = net.createServer();
        srv.on('error', cb);
        srv.listen(0, '127.0.0.1', function() {
            const p = srv.address().port;
            srv.close(function() { cb(null, p); });
        });
    }

    function makeExecError(cmd, code, signal, orgErrMsg) {
        let err = null; // null:success, undefined:did-not-run, Error:failure

        if (orgErrMsg) {
            orgErrMsg = "\n(Original Message: " + orgErrMsg.replace(/\u001b[^m]*?m/g,"").trim() + ")";
        } else {
            orgErrMsg = "";
        }

        if (signal) {
            signal = " (signal: " + signal + ")";
        } else {
            signal = "";
        }

        if (code !== 0 || signal) {
            err = new Error();
            err.message = "Command '" + cmd + "' exited with code=" + code + signal + orgErrMsg;
            err.code = code;

            return errHndl.getErrMsg(err);
        }
        return err;
    }

    novacom.Resolver = Resolver;

    /**
     * @constructor
     */
    function Resolver() {
        /**
         * @property devices
         * This list use to be maintained by novacomd
         */
        this.devices = [];
        this.deviceFileContent = null;
        cliData = new Appdata();
    }

    novacom.Resolver.prototype = {
        /**
         * Load the resolver DB from the filesystem
         * @param {Function} next a common-JS callback invoked when the DB is ready to use.
         */
        load: function(next) {
            log.info("novacom#Resolver()#load()");
            const resolver = this;

            async.waterfall([
                _replaceBuiltinSshKey.bind(resolver),
                _adjustList.bind(resolver),
                _loadString.bind(resolver)
            ], function(err) {
                if (err) {
                    setImmediate(next, err);
                } else {
                    log.silly("novacom#Resolver()#load()", "devices:", resolver.devices);
                    setImmediate(next);
                }
            });

            function _replaceBuiltinSshKey(next) {
                log.silly("novacom#Resolver()#load()#_replaceBuiltinSshKey()");
                const builtinPrvKeyForEmul = path.join(__dirname, "../../files/conf/", 'webos_emul'),
                    userHomePrvKeyForEmul = path.join(keydir, 'webos_emul');

                fs.stat(builtinPrvKeyForEmul, function(err, builtinKeyStat) {
                    if (err) {
                        if (err.code === 'ENOENT') {
                            setImmediate(next);
                        } else {
                            setImmediate(next, err);
                        }
                    } else {
                        fs.stat(userHomePrvKeyForEmul, function(error, userKeyStat) {
                            if (error) {
                                if (error.code === 'ENOENT') {
                                    mkdirp(keydir, function() {
                                        shelljs.cp('-rf', builtinPrvKeyForEmul, keydir);
                                        fs.chmodSync(userHomePrvKeyForEmul, '0600');
                                        setImmediate(next);
                                    });
                                } else {
                                    setImmediate(next, err);
                                }
                            } else {
                                if (builtinKeyStat.mtime.getTime() > userKeyStat.mtime.getTime()) {
                                    shelljs.cp('-rf', builtinPrvKeyForEmul, keydir);
                                    fs.chmodSync(userHomePrvKeyForEmul, '0600');
                                }
                                setImmediate(next);
                            }
                        });
                    }
                });
            }

            /*
             * Add "default" field to list files
             * Set "emulator" to default target
             */
            function _adjustList(next) {
                const defaultTarget = "emulator";
                let inDevices = cliData.getDeviceList(true);

                // count targes does not have "default field"
                const defaultFields = inDevices.filter(function(device) {
                    return (device.default !== undefined );
                });
                if (defaultFields.length < 1) {
                    log.silly("novacom#Resolver()#load()#_adjustList()", "rewrite default field");
                    inDevices = inDevices.map(function(dev) {
                        if (defaultTarget === dev.name) {
                            dev.default = true;
                        } else {
                            dev.default = false;
                        }
                        return dev;
                    });
                    this.save(inDevices);
                }
                setImmediate(next);
            }

            /*
             * Load devices described in the given string
             * (supposed to be a JSON Array).
             */
            function _loadString(next) {
                const inDevices = cliData.getDeviceList(true);

                if (!Array.isArray(inDevices)) {
                    setImmediate(next, errHndl.getErrMsg("INVALID_FILE"));
                    return;
                }

                async.forEach(inDevices, function(inDevice, next) {
                    async.series([
                        resolver._loadOne.bind(resolver, inDevice),
                        resolver._addOne.bind(resolver, inDevice)
                    ], next);
                }, function(err) {
                    if (err) {
                        setImmediate(next, err);
                    } else {
                        setImmediate(next);
                    }
                });
            }
        },

        /*
         * Resolve the SSH private key of the given device
         * into a usable string.  Prefer already fetch keys,
         * then manually-configured OpenSSH one & finally
         * fetch it from a distant device (webOS Pro only).
         */
        _loadOne: function(inDevice, next) {
            if (typeof inDevice.privateKey === 'string') {
                inDevice.privateKeyName = inDevice.privateKey;
                inDevice.privateKey = Buffer.from(inDevice.privateKey, 'base64');
                setImmediate(next);
            } else if (typeof inDevice.privateKey === 'object' && typeof inDevice.privateKey.openSsh === 'string') {
                inDevice.privateKeyName = inDevice.privateKey.openSsh;
                async.waterfall([
                    fs.readFile.bind(this, path.join(keydir, inDevice.privateKey.openSsh), next),
                    function(privateKey, next) {
                        inDevice.privateKey = privateKey;
                        setImmediate(next);
                    }
                ], function(err) {
                    // do not load non-existing OpenSSH private key files
                    if (err) {
                        log.verbose("novacom#Resolver()#_loadOne()", "Unable to find SSH private key named '" +
                                    inDevice.privateKey.openSsh + "' from '" + keydir + " for '" + inDevice.name + "'");
                        inDevice.privateKey = undefined;
                    }
                    setImmediate(next);
                });
            } else if (inDevice.type !== undefined && inDevice.type === 'webospro') {
                // FIXME: here is the place to stream-down the SSH private key from the device
                setImmediate(next, errHndl.getErrMsg("NOT_IMPLEMENTED", "webOS Pro device type handling"));
            } else { // private Key is not defined in novacom-device.json
                if (!inDevice.password) {
                    log.silly("novacom#Resolver()#_loadOne()", "Regist privateKey : need to set a SSH private key in " +
                                keydir + " for'" + inDevice.name + "'");
                }
                inDevice.privateKeyName = undefined;
                inDevice.privateKey = undefined;
                setImmediate(next);
            }
        },

        /*
         * Add given inDevice to the Resolver DB, overwritting
         * any existing one with the same "name:" is needed.
         */
        _addOne: function(inDevice, next) {
            // add the current profile device only
            if (!inDevice.profile || !cliData.compareProfileSync(inDevice.profile)) {
                return setImmediate(next);
            }

            inDevice.display = {
                name: inDevice.name,
                type: inDevice.type,
                privateKeyName: inDevice.privateKeyName,
                passphase: inDevice.passphase,
                description: inDevice.description,
                conn: inDevice.conn || ['ssh'],
                devId: inDevice.id || null
            };

            if (inDevice.username && inDevice.host && inDevice.port) {
                inDevice.display.addr = "ssh://" + inDevice.username + "@" + inDevice.host + ":" + inDevice.port;
            }

            for (const n in inDevice) {
                if (n !== "display") {
                    inDevice.display[n] = inDevice[n];
                }
            }

            // filter-out `this.devices` from the one having the same name as `inDevice`...
            this.devices = this.devices.filter(function(device) {
                return device.name !== inDevice.name;
            });

            // ...hook proper luna interface
            const systemCmd = cliData.getCommandService();
            inDevice.lunaSend = systemCmd.lunaSend;
            inDevice.lunaAddr = systemCmd.lunaAddr;

            // ...and then append `inDevice`
            this.devices.push(inDevice);
            setImmediate(next);
        },


        /**
         * @public
         */
        save: function(devicesData, next) {
            log.info("novacom#Resolver()#save()");
            return cliData.setDeviceList(devicesData, next);
        },

        /**
         * @public
         */
        list: function(next) {
            log.info("novacom#Resolver()#list()");
            setImmediate(next, null, this.devices.map(function(device) {
                return device.display;
            }));
        },

        setTargetName: function(target, printTarget, next) {
            let name = (typeof target === 'string' ? target : target && target.name);
            if (!name) {
                const usbDevices = this.devices.filter(function(device) {
                    return (device.conn && device.conn.indexOf("novacom") !== -1);
                });

                if (usbDevices.length > 1) {
                    return next(errHndl.getErrMsg("CONNECTED_MULTI_DEVICE"));
                }

                // default target priority
                // specified target name > target connected by novacom > user setting > emulator
                if (usbDevices.length > 0 && usbDevices[0].name) {
                    name = usbDevices[0].name;
                } else {
                    const defaultTargets = this.devices.filter(function(device) {
                        return (device.default && device.default === true );
                    });

                    if (defaultTargets.length > 1) {
                        return next(errHndl.getErrMsg("SET_DEFAULT_MULTI_DEVICE"));
                    } else if (defaultTargets.length === 1) {
                        name = defaultTargets[0].name;
                    } else {
                        // if cannot find default target in list, set to "emulator"
                        name = "emulator";
                    }
                }
            }
            if (printTarget) {
                console.log(chalk.green("[Info] Set target device : " + name));
            }
            next(null, 'name', name);
        },

        getDeviceBy: function(key, value, next) {
            log.info("novacom#Resolver()#getDeviceBy()", "key:", key, ", value:", value);
            const devices = this.devices.filter(function(device) {
                return device[key] && device[key] === value;
            });

            if (devices.length < 1) {
                setImmediate(next, errHndl.getErrMsg("UNMATCHED_DEVICE", key, value));
            } else if (typeof next === 'function') {
                setImmediate(next, null, devices[0]);
            } else {
                return devices[0];
            }
        },

        modifyDeviceFile: function(op, target, next) {
            log.info("novacom#Resolver()#modifyDeviceFile()", "op:", op);
            let defaultTarget = "emulator",
                inDevices = cliData.getDeviceList(true);

            if (!target.name) {
                return setImmediate(next, errHndl.getErrMsg("EMPTY_VALUE", "target"));
            }

            if (!Array.isArray(inDevices)) {
                return setImmediate(next, errHndl.getErrMsg("INVALID_FILE"));
            }

            const matchedDevices = inDevices.filter(function(dev) {
                let match = false;
                if (target.name === dev.name) {
                    if (target.profile) {
                        if (target.profile === dev.profile) {
                            match = true;
                        }
                    } else {
                        match = true;
                    }
                }
                return match;
            });

            if (op === 'add') {
                if (matchedDevices.length > 0) {
                    return setImmediate(next, errHndl.getErrMsg("EXISTING_VALUE", "DEVICE_NAME", target.name));
                }

                for (const key in target) {
                    if (target[key] === "@DELETE@") {
                        delete target[key];
                    }
                }

                if (target.default === true) {
                    defaultTarget = target.name;
                } else if (target.default === false) {
                    // new device is not a default target, keep current default target device.
                    defaultTarget = null;
                }

                inDevices = inDevices.concat(target);
            } else if (op === 'remove' || op === 'modify' || op === 'default') {
                if (matchedDevices.length === 0) {
                    return setImmediate(next, errHndl.getErrMsg("INVALID_VALUE", "DEVICE_NAME", target.name));
                }

                if (op === 'remove') {
                    inDevices = inDevices.filter(function(dev) {
                        if (target.name === dev.name) {
                            if (dev.indelible === true) {
                                return setImmediate(next, errHndl.getErrMsg("CANNOT_REMOVE_DEVICE", dev.name));
                            } else {
                                // removed target is not default target, do not set defalut to others
                                if (dev.default === false) {
                                    defaultTarget = null;
                                }
                                return false;
                            }
                        } else {
                            return true;
                        }
                    });
                } else if (op === 'modify') {
                    inDevices = inDevices.map(function(dev) {
                        if (target.name === dev.name) {
                            if (dev.default === true) {
                                // keep current default device as modified target
                                defaultTarget = dev.name;
                            } else {
                                // do not change default device
                                defaultTarget = null;
                            }

                            for (const prop in target) {
                                if (Object.prototype.hasOwnProperty.call(target, prop)) {
                                    dev[prop] = target[prop];
                                    if (dev[prop] === "@DELETE@") {
                                        delete dev[prop];
                                    }
                                }
                            }
                        }
                        return dev;
                    });
                } else if (op === 'default') {
                    inDevices.map(function(dev) {
                        if (target.name === dev.name) {
                            if (target.default === true) {
                                defaultTarget = target.name;
                            }
                        }
                    });
                }
            } else {
                return setImmediate(next, errHndl.getErrMsg("UNKNOWN_OPERATOR", op));
            }

            // Set default target & others to no default target(false)
            if (defaultTarget != null) {
                inDevices = inDevices.map(function(dev) {
                    if (defaultTarget === dev.name) {
                        dev.default = true;
                    } else {
                        dev.default = false;
                    }
                    return dev;
                });
            }
            this.save(inDevices, next);
        }
    };

    /**
     * @constructor
     * @param {String} target the name of the target device to connect to.  "default"
     * @param {Function} next common-js callback, invoked when the Session becomes usable or definitively unusable (failed)
     */
    function Session(target, printTarget, next) {
        if (typeof next !== 'function') {
            throw errHndl.getErrMsg("MISSING_CALLBACK", "next", util.inspect(next));
        }

        const name = (typeof target === 'string' ? target : target && target.name);
        log.info("novacom#Session()", "opening session to '" + (name ? name : "default device") + "'");
        this.resolver = new Resolver();

        async.waterfall([
            this.resolver.load.bind(this.resolver),
            this.resolver.setTargetName.bind(this.resolver, target, printTarget),
            this.resolver.getDeviceBy.bind(this.resolver),
            this.checkConnection.bind(this),
            this.begin.bind(this)
        ], next);
    }

    novacom.Session = Session;

    novacom.Session.prototype = {
        /**
         * Check if socket can be connected
         * This method can be called multiple times.
         * @param {Function} next common-js callback
         */
        checkConnection: function(target, next) {
            let alive = false;
            if (target && target.host && target.port) {
                const socket = new net.Socket();
                socket.setTimeout(2000);
                const client = socket.connect({
                    host: target.host,
                    port: target.port
                });
                client.on('connect', function() {
                    alive = true;
                    client.end();
                    setImmediate(next, null, target);
                });
                client.on('error', function(err) {
                    client.destroy();
                    setImmediate(next, errHndl.getErrMsg(err));
                });
                client.on('timeout', function() {
                    client.destroy();
                    if (!alive) {
                        setImmediate(next, errHndl.getErrMsg("TIME_OUT"));
                    }
                });
            } else {
                setImmediate(next, null, target);
            }
        },

        /**
         * Begin a novacom session with the current target
         * This method can be called multiple times.
         * @param {Function} next common-js callback
         */
        begin: function(target, next) {
            log.verbose("novacom#Session()#begin()", "target:", target.display);
            const self = this;
            this.target = target || this.target;

            if (this.target.conn && (this.target.conn.indexOf('ssh') === -1)) {
                setImmediate(next, null, this);
                return this;
            }

            if (this.target.privateKey === undefined && this.target.password === undefined) {
                return setImmediate(next, errHndl.getErrMsg("NOT_EXIST_SSHKEY_PASSWD"));
            }

            if (!this._connected) {
                this.forwardedPorts = [];
                this._forwards = [];
                this._controlPath = path.join(os.tmpdir(),
                    'ares-ssh-' + process.pid + '-' + Date.now() + '.sock');

                // Establish/validate the connection (and open the control master).
                const child = sshSpawn(this.target, 'true', this._controlPath);
                let errout = '';
                child.stderr.on('data', function(d) { errout += d.toString(); });
                child.on('error', function(err) {
                    setImmediate(next, errHndl.getErrMsg(err));
                });
                child.on('close', function(code) {
                    if (code === 0) {
                        self._connected = true;
                        process.on("SIGHUP", _clearSession);
                        process.on("SIGINT", _clearSession);
                        process.on("SIGQUIT", _clearSession);
                        process.on("SIGTERM", _clearSession);
                        process.on("exit", function() { self._cleanup(); });
                        log.info("novacom#Session()#begin()", "ssh session event: connected");
                        setImmediate(next, null, self);
                    } else {
                        setImmediate(next, errHndl.getErrMsg(
                            new Error("SSH connection failed: " +
                                (errout.replace(/\u001b[^m]*?m/g, "").trim() || ("exit code " + code)))));
                    }
                });
            } else {
                setImmediate(next, null, self);
            }
            return this;

            function _clearSession() {
                log.verbose("novacom#Session()#begin()", "clear Session");
                self.end();
                setTimeout(function() {
                    process.exit();
                }, 500);
            }
        },

        /**
         * @return the resolved device actually in use for this session
         */
        getDevice: function() {
            return this.target;
        },

        /**
         * Suspend the novacom session.  Underlying resources
         * are released (eg. SSH connections are closed).
         */
        end: function() {
            log.info('novacom#Session()#end()', "user-requested termination");
            this._cleanup();
            return this;
        },

        _cleanup: function() {
            if (this._forwards) {
                this._forwards.forEach(function(child) {
                    try { child.kill(); } catch (e) { /* ignore */ }
                });
                this._forwards = [];
            }
            if (this._controlPath) {
                try {
                    execFileSync('ssh',
                        commonSshOpts(this.target, this._controlPath)
                            .concat(['-p', String(this.target.port), '-O', 'exit',
                                     this.target.username + '@' + this.target.host]),
                        { env: opensslEnv(), stdio: 'ignore' });
                } catch (e) { /* master may already be gone */ }
                this._controlPath = null;
            }
            this._connected = false;
        },

        _checkSftp: function(next) {
            // sftp is no longer used (transfers go over `cat` via ssh exec),
            // kept as a no-op for API compatibility.
            setImmediate(next);
        },

        /**
         * Open an interactive login shell on the device, wiring the local
         * terminal straight through (replaces ssh2's Client#shell()).
         * @param {String} cmd optional command to run instead of a login shell
         * @param {Function} next common-js callback invoked when the shell exits
         */
        interactiveShell: function(cmd, next) {
            if (typeof cmd === 'function') {
                next = cmd;
                cmd = null;
            }
            const args = commonSshOpts(this.target, this._controlPath)
                .concat(['-p', String(this.target.port), '-tt',
                         this.target.username + '@' + this.target.host]);
            if (cmd) {
                args.push(cmd);
            }
            const child = spawn('ssh', args, { env: opensslEnv(), stdio: 'inherit' });
            child.on('error', function(err) {
                setImmediate(next, errHndl.getErrMsg(err));
            });
            child.on('close', function() {
                setImmediate(next);
            });
            return child;
        },

        /**
         * Upload a file on the device
         * @param {String} inPath location on the host
         * @param {String} outPath location on the device
         * @param {Function} next common-js callback
         */
        put: function(inPath, outPath, next) {
            log.info("novacom#Session()#put()", "uploding into device:", outPath, "from host:", inPath);
            const inStream = fs.createReadStream(inPath);
            inStream.on('error', function(err) {
                setImmediate(next, errHndl.getErrMsg(err));
            });
            this.streamPut(outPath, inStream, next);
        },

        /**
         * Upload a file on the device via ssh stream
         * @param {String} outPath location on the device
         * @param {ReadableStream} inStream paused host-side source
         * @param {Function} next common-js callback
         */
        streamPut: function(outPath, inStream, next) {
            log.info("novacom#Session()#streamPut()", "streaming into device:" + outPath);
            const cmd = '/bin/cat > "' + outPath + '"';
            this.run(cmd, inStream /* stdin*/ , null /* stdout*/ , process.stderr /* stderr*/ , next);
        },

        /**
         * Upload a file on the device via sftp
         * @param {String} inPath location on the host
         * @param {String} outPath location on the device
         * @param {Function} next common-js callback
         */
        sftpPut: function(inPath, outPath, next) {
            // sftp removed; delegate to the `cat`-over-ssh stream transfer.
            this.put(inPath, outPath, next);
        },

        /**
         * Download file on the device
         * @param {String} inPath location on the device
         * @param {String} outPath location on the host
         * @param {Function} next common-js callback
         */
        get: function(inPath, outPath, next) {
            log.verbose("novacom#Session()#get()", "downloading into host:", outPath, "from target:", inPath);
            const outStream = fs.createWriteStream(outPath);
            outStream.on('error', function(error) {
                setImmediate(next, errHndl.getErrMsg(error));
            });
            this.streamGet(inPath, outStream, next);
        },

        /**
         * Read a file from the device via ssh stream
         * @param {String} inPath the device file path to be read
         * @param {WritableStream} outStream host-side destination to copy the file into
         * @param {Function} next commonJS callback invoked upon completion or failure
         */
        streamGet: function(inPath, outStream, next) {
            log.verbose('novacom#Session()#streamGet()', "streaming from device:" + inPath);
            const cmd = '/bin/cat ' + inPath;
            this.run(cmd, null /* stdin*/ , outStream /* stdout*/ , process.stderr /* stderr*/ , next);
        },

        /**
         * Download file on the device via sftp
         * @param {String} inPath location on the device
         * @param {String} outPath location on the host
         * @param {Function} next common-js callback
         */
        sftpGet: function(inPath, outPath, next) {
            // sftp removed; delegate to the `cat`-over-ssh stream transfer.
            this.get(inPath, outPath, next);
        },

        /**
         * Run a command on the device
         * @param {String} cmd the device command to run
         * @param {stream.ReadableStream} stdin given as novacom process stdin
         * @param {stream.WritableStream} stdout given as novacom process stdout
         * @param {stream.WritableStream} stderr given as novacom process stderr
         * @param {Function} next commonJS callback invoked upon completion or failure
         */
        run: function(cmd, stdin, stdout, stderr, next) {
            this.run_ssh(cmd, {}, stdin, stdout, stderr, next);
        },

        /**
         * Run a command with exec option on the device
         * @param {String} cmd the device command to run
         * @param {Object} opt given as exec option
         * @param {stream.ReadableStream} stdin given as novacom process stdin
         * @param {stream.WritableStream} stdout given as novacom process stdout
         * @param {stream.WritableStream} stderr given as novacom process stderr
         * @param {Function} next commonJS callback invoked upon completion or failure
         */
        runWithOption : function(cmd, opt, stdin, stdout, stderr, next) {
            this.run_ssh(cmd, opt, stdin, stdout, stderr, next);
        },

        /**
         * Run a command on the device
         * @param {String} cmd the device command to run
         * @param {Object} opt given as exec option
         * @param {stream.ReadableStream} stdin given as novacom process stdin
         * @param {stream.WritableStream} stdout given as novacom process stdout
         * @param {stream.WritableStream} stderr given as novacom process stderr
         * @param {Function} next commonJS callback invoked upon completion or failure
         */
        run_ssh: function(cmd, opt, stdin, stdout, stderr, next) {
            log.info("novacom#Session()#run()", "cmd:" + cmd + ", opt:" + JSON.stringify(opt));
            if (typeof next !== 'function') {
                throw errHndl.getErrMsg("MISSING_CALLBACK", "next", util.inspect(next));
            }

            // plumb output
            const write = {},
                obj = {};
                let orgErrMsg;

            if (!stdout) {
                log.silly("novacom#Session()#run()", "stdout: none");
                write.stdout = function() {};
            } else if (stdout instanceof stream.Stream) {
                log.silly("novacom#Session()#run()", "stdout: stream");
                write.stdout = stdout.write;
                obj.stdout = stdout;
            } else if (stdout instanceof Function) {
                log.silly("novacom#Session()#run()", "stdout: function");
                write.stdout = stdout;
            } else {
                setImmediate(next, errHndl.getErrMsg("INVALID_VALUE", "stdout", util.inspect(stdout)));
            }

            if (!stderr) {
                log.silly("novacom#Session()#run()", "stderr: none");
                write.stderr = function() {};
            } else if (stderr instanceof stream.Stream) {
                log.silly("novacom#Session()#run()", "stderr: stream");
                write.stderr = stderr.write;
                obj.stderr = stderr;
            } else if (stderr instanceof Function) {
                log.silly("novacom#Session()#run()", "stderr: function");
                write.stderr = stderr;
            } else {
                setImmediate(next, errHndl.getErrMsg("INVALID_VALUE", "stderr", util.inspect(stderr)));
            }

            // execute command via system ssh
            const extraArgs = (opt && opt.pty) ? ['-tt'] : [];
            const child = sshSpawn(this.target, cmd, this._controlPath, extraArgs);
            let done = false;

            child.stdout.on('data', function(data) {
                log.verbose("novacom#Session()#run()", "on data (stdout)");
                write.stdout.bind(obj.stdout)(data);
            });
            child.stderr.on('data', function(data) {
                log.verbose("novacom#Session()#run()", "on data (stderr)");
                // Match the original ssh2 behaviour: remote stderr is captured
                // for error reporting only, not streamed to the stderr sink
                // (callers may pass an error-callback there).
                orgErrMsg = data.toString();
            });

            child.on('error', function(err) {
                if (done) { return; }
                done = true;
                setImmediate(next, errHndl.getErrMsg(err));
            });

            child.on('close', function(code, signal) {
                log.silly("novacom#Session()#run()", "event close code:" + code + ', signal:' + signal + " (cmd:" + cmd + ")");
                if ((stdout !== process.stdout) && (stdout instanceof stream.Stream)) {
                    stdout.end();
                }
                if ((stderr !== process.stderr) && (stderr instanceof stream.Stream)) {
                    stderr.end();
                }
                if (done) { return; }
                done = true;
                const err = makeExecError(cmd, code, signal, orgErrMsg);
                setImmediate(next, err);
            });

            if (stdin) {
                log.verbose("novacom#Session()#run()", "resuming input");
                stdin.pipe(child.stdin);
                child.stdin.on('error', function() { /* ignore EPIPE on early exit */ });
            } else {
                try { child.stdin.end(); } catch (e) { /* ignore */ }
            }
        },

        /**
         * Run a command on the device considerless return stdout
         * @param {String} cmd the device command to run
         * @param {Function} callback invoked upon exit event
         * @param {Function} next commonJS callback invoked upon completion or failure
         */
        runNoHangup: function(cmd, cbData, cbExit, next) {
            this.runNoHangup_ssh(cmd, cbData, cbExit, next);
        },

        /**
         * Run a command on the device considerless return stdout
         * @param {String} cmd the device command to run
         * @param {Function} callback invoked upon exit event
         * @param {Function} next commonJS callback invoked upon completion or failure
         */
        runNoHangup_ssh: function(cmd, cbData, cbExit, next) {
            log.info("novacom#Session()#runNoHangup()", "cmd=" + cmd);
            if (arguments.length < 2) {
                throw errHndl.getErrMsg("MISSING_CALLBACK", "next");
            }

            for (const arg in arguments) {
                if (typeof arguments[arg] === 'undefined') {
                    delete arguments[arg];
                    arguments.length--;
                }
            }

            switch (arguments.length) {
                case 2:
                    next = cbData;
                    cbData = cbExit = null;
                    break;
                case 3:
                    next = cbExit;
                    cbExit = cbData;
                    cbData = null;
                    break;
                default:
                    break;
            }

            if (typeof next !== 'function') {
                throw errHndl.getErrMsg("MISSING_CALLBACK", "next", util.inspect(next));
            }

            // execute command via system ssh
            const child = sshSpawn(this.target, cmd, this._controlPath);

            child.stdout.on('data', function(data) {
                log.verbose("novacom#Session()#runNoHangup()#onData", data.toString());
                if (cbData) cbData(data);
            });
            child.stderr.on('data', function(data) {
                log.verbose("novacom#Session()#runNoHangup()#onData#stderr#", data.toString());
                if (cbData) cbData(data);
            });

            if (cbExit) {
                child.on('close', function(code, signal) {
                    log.verbose("novacom#Session()#runNoHangup()", "event close code=" + code + ', signal=' + signal + " (cmd: " + cmd + ")");
                    cbExit(makeExecError(cmd, code, signal));
                });
            }
            child.on('error', function(err) {
                if (cbExit) cbExit(errHndl.getErrMsg(err));
            });
            try { child.stdin.end(); } catch (e) { /* ignore */ }
            setImmediate(next);
        },

        /**
         * Forward the given device port on the host.
         * As any other public method, this one can be called
         * only once the ssh session has emitted the 'ready'
         * event, so as part of the Session()#next callback.
         * @public
         * @param {Function} next commonJS callback invoked upon completion or failure
         */
        forward: function(devicePort, localPort, forwardName, next) {
            log.info("novacom#Session()#forward()", "devicePort:", devicePort, ", localPort:", localPort);
            const session = this;
            let registerName = null;

            if (typeof forwardName === 'function') {
                next = forwardName;
            } else if (forwardName) {
                registerName = forwardName;
            }

            // Reuse an existing forward to the same device port / name.
            const existing = session.forwardedPorts.filter(function(forwardItem) {
                return (forwardItem.device === devicePort && forwardItem.name === registerName);
            });
            if (existing.length > 0) {
                return setImmediate(next);
            }

            function openForward(lp) {
                // A dedicated `ssh -N -L` child, reusing the control master.
                const child = sshSpawn(session.target, null, session._controlPath,
                    ['-N', '-L', lp + ':127.0.0.1:' + devicePort]);
                child.on('error', function(err) {
                    log.warn("novacom#Session()#forward()", "forward error:", err);
                });
                session._forwards.push(child);
                session.forwardedPorts.push({
                    name: registerName,
                    local: lp,
                    device: devicePort
                });
                // Give ssh a moment to establish the listener before returning.
                setTimeout(function() { setImmediate(next); }, 400);
            }

            if (localPort && localPort !== 0) {
                openForward(localPort);
            } else {
                freePort(function(err, p) {
                    if (err) {
                        return setImmediate(next, errHndl.getErrMsg(err));
                    }
                    openForward(p);
                });
            }
        },

        getLocalPortByDevicePort: function(remotePort) {
            const session = this;
            let found = null;
            session.forwardedPorts.forEach(function(portItem) {
                if (portItem.device === remotePort) {
                    found = portItem.local;
                    return;
                }
            });
            return found;
        },

        getLocalPortByName: function(queryName) {
            const session = this;
            let found = null;
            session.forwardedPorts.forEach(function(portItem) {
                if (portItem.name === queryName) {
                    found = portItem.local;
                    return;
                }
            });
            return found;
        },

        runHostedAppServer: function(url, next) {
            server.runServer(url, 0, function(err, serverInfo) {
                if (serverInfo && serverInfo.port) {
                    this.setHostedAppServerPort(serverInfo.port);
                }
                next(err);
            }.bind(this));
        },

        setHostedAppServerPort: function(port) {
            this.hostedAppServerPort = port;
        },

        getHostedAppServerPort: function() {
            return this.hostedAppServerPort;
        }
    };

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = novacom;
    }
}());
