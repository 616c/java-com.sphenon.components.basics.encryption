package com.sphenon.basics.encryption;

/****************************************************************************
  Copyright 2001-2024 Sphenon GmbH

  Licensed under the Apache License, Version 2.0 (the "License"); you may not
  use this file except in compliance with the License. You may obtain a copy
  of the License at http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
  License for the specific language governing permissions and limitations
  under the License.
*****************************************************************************/

import com.sphenon.basics.context.*;
import com.sphenon.basics.context.classes.*;
import com.sphenon.basics.configuration.*;
import com.sphenon.basics.message.*;
import com.sphenon.basics.notification.*;
import com.sphenon.basics.customary.*;

public class EncryptionPackageInitialiser {

    static protected boolean initialised = false;

    static {
        initialise(RootContext.getRootContext());
    }

    static public void initialise (CallContext context) {
        
        if (initialised == false) {
            initialised = true;

            Configuration.loadDefaultProperties(context, com.sphenon.basics.encryption.EncryptionPackageInitialiser.class);
        }
    }

    static protected Configuration config;

    static public Configuration getConfiguration (CallContext context) {
        if (config == null) {
            config = Configuration.create(RootContext.getInitialisationContext(), "com.sphenon.basics.encryption");
        }
        return config;
    }
}
