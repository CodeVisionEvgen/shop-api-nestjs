// import { ConfigService } from '@nestjs/config';
import { JwtModuleOptions } from '@nestjs/jwt';

export const JwtRegisterAsyncOptions = () // configService: ConfigService,
: JwtModuleOptions => {
  return {
    global: true,
  };
};
