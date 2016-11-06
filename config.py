#!/usr/bin/python

# contains fuzzer configuration, parameters can be accessed as attributes
class Config:

    # read arguments returned by argparse.ArgumentParser
    def readargs(self, args):
        self.args = vars(args)

        if args.test:
            parts = args.test.split(':')
            if len(parts) == 1:
                self.args['start_test'] = int(parts[0])
                self.args['end_test'] = int(parts[0])
            elif len(parts) == 2:
                self.args['start_test'] = int(parts[0])
                if parts[1] == '' or parts[1] == 'infinite':
                    self.args['end_test'] = float('inf')
                else:
                    self.args['end_test'] = int(parts[1])
            else:
                raise Exception('Could not parse --test value, too many colons')
        else:
            self.args['start_test'] = 0
            self.args['end_test'] = float('inf')

        parts = args.ratio.split(':')
        if len(parts) == 1:
            self.args['min_ratio'] = float(parts[0])
            self.args['max_ratio'] = min_ratio
        elif len(parts) == 2:
            self.args['min_ratio'] = float(parts[0])
            self.args['max_ratio'] = float(parts[1])
        else:
            raise Exception('Could not parse --ratio value, too many colons')

    def nofuzzer(self):
        if (not self.common and not self.settings and not self.headers and not self.hpack and
            not self.priority and not self.rst_stream and not self.data and
            not self.push_promise and not self.ping and not self.goaway and
            not self.window_update and not self.continuation and not self.all):
            return True
        else:
            return False

    def __getattr__(self, name):
        return self.args[name]

current = Config()
