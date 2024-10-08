import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class EmailValidation {
  @PrimaryGeneratedColumn()
  Id: number;

  @Column({
    nullable: false,
  })
  FirstName: string;

  @Column({
    nullable: true,
  })
  LastName: string;
  @Column({
    nullable: false,
  })
  Email: string;

  @Column()
  Password: string;

  @Column({
    nullable: false,
  })
  Provider: string;

  @Column({
    nullable: false,
  })
  Avatar: string;

  @Column({
    nullable: false,
  })
  CallBackUUID: string;
}
