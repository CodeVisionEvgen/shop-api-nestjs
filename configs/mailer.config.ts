import { MailerOptions } from '@nestjs-modules/mailer';
import { PugAdapter } from '@nestjs-modules/mailer/dist/adapters/pug.adapter';
import { ConfigService } from '@nestjs/config';
import { join } from 'path';

export const MailerAsyncConfig = (
  configService: ConfigService,
): MailerOptions => {
  return {
    transport: {
      host: 'smtp.gmail.com',
      port: 587,
      auth: {
        user: configService.get('MAILER_USER_NOREPLY'),
        pass: configService.get('MAILER_PASS_NOREPLY'),
      },
    },
    defaults: {
      from: configService.get('MAILER_TITLE_NOREPLY'),
    },
    template: {
      dir: join(process.cwd(), 'templates'),
      adapter: new PugAdapter(),
      options: {
        strict: true,
      },
    },
  };
};
